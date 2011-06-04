require 'addressable/uri'

class RoipTextAccessToken
  include RoipTokenAuth
  attr_reader :access_token, :scope, :valid_to, :signature, :refresh
  
  # Can initialize with either a hash or a JSON string
  def initialize(hashOrJson)
    if !hashOrJson.respond_to? :keys
      hashOrJson = JSON.parse hashOrJson
    end
    hashOrJson.keys.each { |name| instance_variable_set "@" + name.to_s, hashOrJson[name] }
  end
  
  
  def valid?(path)
    scopeURI = Addressable::URI.parse(@scope.gsub('"', ''))
    scopePQ = scopeURI.path + (scopeURI.query ? ("?" + scopeURI.query) : "")
    reqUriURI = Addressable::URI.parse(path)
    reqUriPQ = reqUriURI.path + (reqUriURI.query ? ("?" + reqUriURI.query) : "")
    if (!reqUriPQ.match(Regexp.escape(scopePQ)).nil? &&
    (Time.zone.parse(@valid_to).future?) && dss_validate_signature)
      Rails::logger.debug "Token is valid"
      return true
    else
      Rails::logger.debug "Token is invalid"
      return false
    end
  end
  
  private
  
  def token_digest
    OpenSSL::Digest::SHA1.digest(@access_token +
    @scope +
    @valid_to)
  end
    
    
  def dss_validate_signature  
    cas_public_dss_keys.each do |pktext| # Set an array of pem keys in the initializer
      pubkey = OpenSSL::PKey::DSA.new(pktext)
      if (pubkey.sysverify(token_digest, Base64.urlsafe_decode64(@signature)))
        Rails::logger.debug "DSS Signature is valid"
        return true
      end
    end
    Rails::logger.warn "DSS Signature #{@signature} is NOT valid"
    return false
  end
end
