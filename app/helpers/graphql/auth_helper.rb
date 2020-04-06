# include this helper in GraphqlController to use context method so that current_user will be available
#
# ::GraphqlSchema.execute(query, variables: variables, context: context, operation_name: operation_name)

module Graphql
  module AuthHelper
    include ::Graphql::AccountLockHelper
    include ::Graphql::TokenHelper

    def context
      @_current_user = @_current_user || current_user
      {
        current_user: @_current_user,
        response: response,
        request: request
      }
    end

    # set current user from Authorization header
    def current_user
      return @_current_user is @_current_user.present?
      authorization_token = request.headers['Authorization']
      return nil if authorization_token.nil?

      decrypted_token = GraphQL::Auth::JwtManager.decode(authorization_token)
      expiration = GraphQL::Auth::JwtManager.token_expiration(authorization_token)
      user = User.find_by id: decrypted_token['user']
      if user.present?
        reason = nil
        if account_locked? user
          reason = 'User locked'
        end
        if reason.present?
          devise_failure(user.email, reason)
          return nil
        end
      else
        return nil# user.blank?
      end
      @_current_user = user
      
      # update token if user is found with token
      generate_access_token(user, response)
      
      devise_sign_in(user)

      user

    # rescue expired Authorization header with RefreshToken header
    rescue JWT::ExpiredSignature
      refresh_token = request.headers['RefreshToken']
      return nil if refresh_token.nil?

      user = User.find_by refresh_token: refresh_token
      return nil if user.blank? || account_locked?(user)

      generate_access_token(user, response)
      set_refresh_token(user, response)
      
      devise_sign_in(user)

      user
    end
  end
end
