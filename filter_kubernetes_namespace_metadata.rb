require 'fluent/filter'

module Fluent
  class PassThruFilter < Filter
    K8_POD_CA_CERT = 'ca.crt'
    K8_POD_TOKEN = 'token'

    # Register this filter as "kubernetes_namespace_metadata"
    Fluent::Plugin.register_filter('kubernetes_namespace_metadata', self)

    # config_param works like other plugins
    config_param :kubernetes_url, :string, default: nil
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
      require 'kubeclient'

      @tag_to_kubernetes_name_regexp_compiled = Regexp.compile(@tag_to_kubernetes_name_regexp)

    end

    def start
      super
      # This is the first method to be called when it starts running
      # Use it to allocate resources, etc.
    end

    def shutdown
      super
      # This method is called when Fluentd is shutting down.
      # Use it to free up resources, etc.
    end

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
  end
end
