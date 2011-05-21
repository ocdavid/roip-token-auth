class DummyController < ApplicationController
  
  before_filter :roip_token_filter
  
  def index
    render :text => "OK!"
  end
end