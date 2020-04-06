# include this helper in GraphqlController to use context method so that current_user will be available
#
# ::GraphqlSchema.execute(query, variables: variables, context: context, operation_name: operation_name)

module Graphql
  module TokenHelper
    def generate_access_token(user, response)
      token = GraphQL::Auth::JwtManager.issue_with_expiration({ user: user.id }) # TODO use uuid
      response.set_header 'Authorization', token
      response.set_header 'Expires', GraphQL::Auth::JwtManager.token_expiration(token)
    end
    
    def devise_sign_in(user)
      # sign in via devise whenever we log in
      sign_in(user, scope: :user)
    end
    
    def devise_failure(email, reason)
      request.params[:user] = { email: email }
      opts = { message: reason, scope: :user }
      Warden::Manager._run_callbacks(:before_failure, request.env, opts)
    end

    def set_refresh_token(user, response)
      refresh_token = user.refresh_token.presence || GraphQL::Auth::JwtManager.issue_without_expiration({ user: user.id })
      user.update_column :refresh_token, refresh_token
      response.set_header 'RefreshToken', refresh_token
    end

    def set_current_user(user)
      context[:current_user] = user
    end

    def delete_refresh_token(user)
      user.update_column :refresh_token, nil if user.refresh_token.present?
    end
    
    def set_google_secret(user)
      user.set_google_secret
    end
    
    def verify_google_code(user, code)
      user.google_authentic?(code)
    end
  end
end
