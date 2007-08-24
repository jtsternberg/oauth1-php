module OAuth
  class Base
    def initialize(consumer_key, consumer_secret, token, token_secret, request_method, request_uri, params, nonce, timestamp, sig_alg='hmac-sha1')
      local_variables.each { |var| @config[var] = eval var }
    end

    def method_missing(method, *args)
      return @config[method.to_s] if @config.keys.include?(method.to_s)
      super(method, *args)
    end

    def signature_string(skip_consumer_secret = false)
      signature_array = []
      %w( consumer_secret consumer_key token token_secret request_method
          request_uri normalized_request_parameters nonce timestamp ).each do |sig_part|
        next if sig_part == 'consumer_secret' && skip_consumer_secret
        signature_array << escape(sig_part) + "=" + escape(self.send(sig_part))
      end
      signature_array.join('&') # i don't know if this should be .join("&amp;")
    end

    def normalized_request_parameters
      sorted_params = @params.sort { |a,b| a[0].to_s <=> b[0].to_s }
      sorted_params.map! { |k,v| escape(k) + "=" + escape(v) }
      sorted_params.join("&") # i don't know if this should be .join("&amp;")
    end

    def ==(cmp_signature)
      signature == cmp_signature
    end

    def escape(v)
      # I don't know if this is the escaping algorithm ben meant. I think it
      # acheives the same thing, but it might not be the same.
      CGI.escape(v)
    end

    def signature
      case sig_alg
      when 'md5', 'sha1'
        require "digest/#{sig_alg}"
        klass = eval("Digest::#{sig_alg}")
        klass.hexdigest(signature_string)
      when 'hmac-md5', 'hmac-rmd160', 'hmac-sha1', 'hmac-sha2'
        require sig_alg.gsub(/-/, '/')
        klass = eval(sig_alg.gsub(/-/, '::').upcase)
        klass.hexdigest(consumer_secret, signature_string(true))
      when 'rsa'
        raise "RSA Signing is unimplemented."
      else raise "Unknown signature algorithm: #{sig_alg}"
      end
    end
  end

  class Client < Base
    def initialize(consumer_key, consumer_secret, token, token_secret, request_method, request_uri, params, nonce = nil, timestamp = nil, sig_alg='hmac-sha1')
      super(token, secret, key, request_method, request_uri, params, timestamp || self.timestamp, nonce || self.generate_nonce, sig_alg)
    end

    def request_params
      { :oauth_consumer_key => consumer_key,
        :oauth_token        => token,
        :oauth_sig          => signature,
        :oauth_nonce        => @nonce,
        :oauth_ts           => @timestamp,
        :oauth_sigalg       => @sig_alg }
    end

    def timestamp
      Time.now.to_i
    end

    def generate_nonce
      rand(2**128)
    end
  end
end

