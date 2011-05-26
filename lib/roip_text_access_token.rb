require 'addressable/uri'

class RoipTextAccessToken
  include RoipTokenAuth
  attr_reader :access_token, :scope, :valid_to, :signature, :namespace, :refresh
  
  def initialize(h)
    if h.respond_to? :keys
      h.keys.each { |name| instance_variable_set "@" + name.to_s, h[name] }
    end
    
  end
  
  def valid?(path)
    scopeURI = Addressable::URI.parse(self.scope.gsub('"', ''))
    scopePQ = scopeURI.path + (scopeURI.query ? ("?" + scopeURI.query) : "")
    reqUriURI = Addressable::URI.parse(path)
    reqUriPQ = reqUriURI.path + (reqUriURI.query ? ("?" + reqUriURI.query) : "")
    if (!reqUriPQ.match(Regexp.escape(scopePQ)).nil? &&
    (Time.zone.parse(self.valid_to).future?) && dss_validate_signature && validate_namespaces)
      Rails::logger.debug "Token is valid"
      return true
    else
      Rails::logger.debug "Token is invalid"
      return false
    end
  end
  
  private
  
  
  def token_digest
    OpenSSL::Digest::SHA1.digest(self.access_token +
    self.scope +
    self.valid_to +
    (self.namespace.present? ? self.namespace : ""))
  end
    
    
  def dss_validate_signature
    # TODO: support >1 CAS by iterating through keys array
    pubkey = OpenSSL::PKey::DSA.new(OpenSSL::PKey::DSA.new(cas_public_dss_keys[0]))
    if (pubkey.sysverify(token_digest, Base64.decode(self.signature)))
      Rails::logger.debug "DSS Signature is valid"
      return true
    else
      Rails.logger.debug "DSS Signature #{self.signature} is NOT valid"
      return false
    end
  end
  
  
  def validate_namespaces
    return true if ! self.namespace
    if !::RoipTokenAuth::ok_namespaces.empty? && !ok_namespaces.include?(self.namespace)
      Rails::logger.warn "Found unacceptable namespace of #{self.namespace} in Access Token"
      return false
    end
    true
  end
  
  
  # The following two methods are DEPRECATED pre-DSS versions
  
  def validate_signature
    [ self.access_token, self.scope, self.valid_to ].map { |i| return false if ! i }
    if sign(self.access_token +
      self.scope +
      self.valid_to +
      (self.namespace.present? ? self.namespace : "")) == self.signature
      Rails::logger.debug "Signature is valid"
      return true
    else
      Rails::logger.debug "Signature = #{self.signature} is NOT valid"
      return false
    end
  end
  
  
  def sign(str)
    "Provisional-" + ActiveSupport::Base64.encode64s(Digest::SHA2.new(512).digest(str + ::RoipTokenAuth::SIGNINGSECRET))
  end
end
