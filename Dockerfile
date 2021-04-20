FROM fluent/fluentd:v1.12-debian-1

# Use root account to use apt
USER root

# below RUN includes plugin as examples elasticsearch is not required
# you may customize including plugins as you wish
RUN buildDeps="sudo make gcc g++ libc-dev" \
 && apt-get update \
 && apt-get install -y --no-install-recommends $buildDeps \
 && apt-get install -y \
        nmap \
 #       vim \
 && sudo gem install fluent-plugin-elasticsearch \
 && sudo gem install fluent-plugin-kubernetes_metadata_filter \
 && sudo gem install fluent-plugin-rewrite-tag-filter \
 && sudo gem sources --clear-all \
 && SUDO_FORCE_REMOVE=yes \
    apt-get purge -y --auto-remove \
                  -o APT::AutoRemove::RecommendsImportant=false \
                  $buildDeps \
# && mkdir -p /fluentd/etc/ \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /tmp/* /var/tmp/* /usr/lib/ruby/gems/*/cache/*.gem \
 && mkdir -p /etc/fluent/plugin \
 && && chown -R fluent /etc/fluent && chgrp -R fluent /etc/fluent



ADD https://github.com/StribPav/haproxy-parse/blob/main/filter_kubernetes_namespace_metadata.rb /fluentd/plugins
ADD https://github.com/StribPav/haproxy-parse/blob/main/filter_kubernetes_namespace_metadata.rb /etc/fluent/plugin
#COPY entrypoint.sh /bin/

USER fluent
ENTRYPOINT ["tini",  "--", "/bin/entrypoint.sh"]
CMD ["fluentd"]
