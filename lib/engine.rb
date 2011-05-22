require 'rails'
require 'roip_token_auth.rb'

module RoipTokenAuth
  class Engine < Rails::Engine
    initializer "roip_token_auth.app_controller" do |app|
      ActiveSupport.on_load(:action_controller) do
        include RoipTokenAuth::Controllers::Helpers
      end
    end
  end
end
