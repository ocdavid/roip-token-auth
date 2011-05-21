class RoipTextAccessToken
  attr_reader :token, :scope, :valid_to, :signature, :namespace, :refresh
  
  def initialize(h)
    if h.respond_to? :keys
      h.keys.each { |name| instance_variable_set "@" + name.to_s, h[name] }
    end
  end
  
  def valid?(path, ok_namespaces)
    logger.debug "Validating token against path of #{path}, ok_namespaces of #{::RoipTokenAuth::ok_namespaces}"
    
    scopeURI = Addressable::URI.parse(self.scope.gsub('"', ''))
    scopePQ = scopeURI.path + (scopeURI.query ? ("?" + scopeURI.query) : "")
    reqUriURI = Addressable::URI.parse(path)
    reqUriPQ = reqUriURI.path + (reqUriURI.query ? ("?" + reqUriURI.query) : "")
    if (!reqUriPQ.match(Regexp.escape(scopePQ)).nil? &&
    (Time.zone.parse(self.valid_to).future?) &&
    validate_signature(oauth_token) && 
    validate_namespaces(oauth_token, accept_namespaces)) 
      logger.debug "Token is valid"
      return true
    else
      logger.debug "Token is invalid"
      return false
    end
  end
  
  private
  
  def validate_signature
    logger.debug "About to validate_signature for " + self.inspect
    if sign(self.token +
      self.scope +
      self.valid_to.to_s +
      (self.namespace ? tokhash["namespace"] : "")) == self.signature
      logger.debug "Signature is valid"
      return true
    else
      logger.debug "Signature = #{self.signature} is NOT valid"
      return false
    end
  end
  
  def sign(str)
    "Provisional-" + ActiveSupport::Base64.encode64s(Digest::SHA2.new(512).digest(str + ::RoipTokenAuth::SIGNINGSECRET))
  end
  
  
  def validate_namespaces
    if !::RoipTokenAuth::ok_namespaces.empty? && !::RoipTokenAuth::ok_namespaces.include?(self.namespace)
      logger.warn "In validate_namespaces, unacceptable namespace of #{self.namespace} in Access Token"
      return false
    end
    true
  end
end
