require 'fluent/plugin/filter'
require 'resolv'

module Fluent
  class PassThruFilter < Filter
    K8_POD_CA_CERT = 'ca.crt'
    K8_POD_TOKEN = 'token'

    # Register this filter as "kubernetes_namespace_metadata"
    Fluent::Plugin.register_filter('kubernetes_namespace_metadata', self)

    # config_param works like other plugins
    config_param :kubernetes_url, :string, default: nil
    config_param :cache_size, :integer, default: 1000
    config_param :cache_ttl, :integer, default: 60 * 60
  	config_param :apiVersion, :string, default: 'v1'
    config_param :client_cert, :string, default: nil
    config_param :client_key, :string, default: nil
    config_param :ca_file, :string, default: nil
    config_param :verify_ssl, :bool, default: true
  	config_param :bearer_token_file, :string, default: nil
  	config_param :secret_dir, :string, default: '/var/run/secrets/kubernetes.io/serviceaccount'
  	config_param :tag_to_kubernetes_name_regexp,
                 :string,
                 default: 'var\.log\.containers\.(?<pod_name>[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*)_(?<namespace>[^_]+)_(?<container_name>.+)-(?<docker_id>[a-z0-9]{64})\.log$'

    def configure(conf)
      super
      # do the usual configuration here
      def log.trace?
        level == Fluent::Log::LEVEL_TRACE
      end

      require 'kubeclient'
      require 'lru_redux'
      @stats = KubernetesMetadata::Stats.new

      # Use the namespace UID as the key to fetch a hash containing namespace metadata
      @namespace_cache = LruRedux::TTL::ThreadSafeCache.new(@cache_size, @cache_ttl)

      @tag_to_kubernetes_name_regexp_compiled = Regexp.compile(@tag_to_kubernetes_name_regexp)

      if @cache_ttl < 0
        log.info 'Setting the cache TTL to :none because it was <= 0'
        @cache_ttl = :none
      end

      # Use Kubernetes default service account if we're in a pod.
      if @kubernetes_url.nil?
        log.debug 'Kubernetes URL is not set - inspecting environ'

        env_host = ENV['KUBERNETES_SERVICE_HOST']
        env_port = ENV['KUBERNETES_SERVICE_PORT']
        if present?(env_host) && present?(env_port)
          if env_host =~ Resolv::IPv6::Regex
            # Brackets are needed around IPv6 addresses
            env_host = "[#{env_host}]"
          end
          @kubernetes_url = "https://#{env_host}:#{env_port}/api"
          log.debug "Kubernetes URL is now '#{@kubernetes_url}'"
        else
          log.debug 'No Kubernetes URL could be found in config or environ'
        end
      end

      # Use SSL certificate and bearer token from Kubernetes service account.
      if Dir.exist?(@secret_dir)
        log.debug "Found directory with secrets: #{@secret_dir}"
        ca_cert = File.join(@secret_dir, K8_POD_CA_CERT)
        pod_token = File.join(@secret_dir, K8_POD_TOKEN)

        if !present?(@ca_file) && File.exist?(ca_cert)
          log.debug "Found CA certificate: #{ca_cert}"
          @ca_file = ca_cert
        end

        if !present?(@bearer_token_file) && File.exist?(pod_token)
          log.debug "Found pod token: #{pod_token}"
          @bearer_token_file = pod_token
        end
      end

      if present?(@kubernetes_url)
        ssl_options = {
          client_cert: present?(@client_cert) ? OpenSSL::X509::Certificate.new(File.read(@client_cert)) : nil,
          client_key: present?(@client_key) ? OpenSSL::PKey::RSA.new(File.read(@client_key)) : nil,
          ca_file: @ca_file,
          verify_ssl: @verify_ssl ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
        }

        if @ssl_partial_chain
          # taken from the ssl.rb OpenSSL::SSL::SSLContext code for DEFAULT_CERT_STORE
          require 'openssl'
          ssl_store = OpenSSL::X509::Store.new
          ssl_store.set_default_paths
          flagval = if defined? OpenSSL::X509::V_FLAG_PARTIAL_CHAIN
                      OpenSSL::X509::V_FLAG_PARTIAL_CHAIN
                    else
                      # this version of ruby does not define OpenSSL::X509::V_FLAG_PARTIAL_CHAIN
                      0x80000
                    end
          ssl_store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK_ALL | flagval
          ssl_options[:cert_store] = ssl_store
        end

        auth_options = {}

        if present?(@bearer_token_file)
          bearer_token = File.read(@bearer_token_file)
          auth_options[:bearer_token] = bearer_token
        end

        log.debug 'Creating K8S client'
        @client = Kubeclient::Client.new(
          @kubernetes_url,
          @apiVersion,
          ssl_options: ssl_options,
          auth_options: auth_options,
          as: :parsed_symbolized
        )

        begin
          @client.api_valid?
        rescue KubeException => e
          raise Fluent::ConfigError, "Invalid Kubernetes API #{@apiVersion} endpoint #{@kubernetes_url}: #{e.message}"
        end

        if @watch
          namespace_thread = Thread.new(self, &:set_up_namespace_thread)
          namespace_thread.abort_on_exception = true
        end
      end

      @annotations_regexps = []
      @annotation_match.each do |regexp|
        @annotations_regexps << Regexp.compile(regexp)
      rescue RegexpError => e
        log.error "Error: invalid regular expression in annotation_match: #{e}"
      end
    end

#    def start
#      super
      # This is the first method to be called when it starts running
      # Use it to allocate resources, etc.
#    end

#    def shutdown
#      super
      # This method is called when Fluentd is shutting down.
      # Use it to free up resources, etc.
#    end

    def filter_stream(tag, es)
      return es if (es.respond_to?(:empty?) && es.empty?) || !es.is_a?(Fluent::EventStream)
      new_es = Fluent::MultiEventStream.new
      tag_match_data = tag.match(@tag_to_kubernetes_name_regexp_compiled) unless @use_journal
      tag_metadata = nil
      es.each do |time, record|
        if tag_match_data && tag_metadata.nil?
          metadata = fetch_namespace_metadata(tag_match_data['namespace'])
        end
        record = record.merge(metadata) if metadata
        new_es.add(time, record)
      end
      dump_stats
      new_es
    end

    # copied from activesupport
    def present?(object)
      object.respond_to?(:empty?) ? !object.empty? : !!object
    end
  end
end
