module RoipTokenAuth
  class TokenFilter
    include Rack::Utils
    def initialize(app)
      @app = app
    end

    # Should be usable by any Rack app including Rails.  Accept an access token from the Authorization: header only.

    def call(env)

      logger = Logger.new("/tmp/mylog")
      logger.level = Logger::DEBUG

      @status, @headers, @response = @app.call(env)
      
      if env["HTTP_AUTHORIZATION"] && ((oauth_string = env["HTTP_AUTHORIZATION"].gsub(/OAuth /, "").size > 0))
        theToken = RoipTextAccessToken.new(JSON.parse oauth_string)
      end

      path = "localhost"
      ok_namespaces = [ nil ]
      
      if theToken && theToken.valid?(path, ok_namespaces)
        [status, headers, self]
      else
        # TODO: Allow the parent app to set a "failure" route or app
        [401, {"WWW-Authenticate" => "Oauth", "Content-Type" => "text/html"}, "Invalid RoIP Token"]
      end
    end

    def each(&block)
      @response.each(&block)
    end
  end

  class RoipTextAccessToken
    attr_reader :token, :scope, :valid_to, :signature, :namespace, :refresh
    
    def initialize(h)
      if h.respond_to? :keys
        h.keys.each { |name| instance_variable_set "@" + name.to_s, h[name] }
      end
    end
    
    def valid?(path, ok_namespaces)
      false
    end
  end
end
