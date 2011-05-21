require 'token_filter.rb'
require 'rails'

module RoipTokenAuth
  class Engine < Rails::Engine
    initializer "roip_token_auth.add_middleware" do |app|
      app.middleware.use RoipTokenAuth::TokenFilter
    end
  end
end
