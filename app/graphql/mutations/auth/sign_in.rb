# frozen_string_literal: true

class Mutations::Auth::SignIn < GraphQL::Schema::Mutation
  include ::Graphql::AccountLockHelper
  include ::Graphql::TokenHelper

  argument :email, String, required: true do
    description "The user's email"
  end

  argument :password, String, required: true do
    description "The user's password"
  end
  
  argument :google_authenticator_code, String, required: false do
    description "Code from Google Authenticator if two-factor authentication is enabled"
  end

  argument :remember_me, Boolean, required: false do
    description "User's checkbox to be remembered after connection timeout"
  end

  field :errors, [::Types::Auth::Error], null: false
  field :success, Boolean, null: false
  field :user, GraphQL::Auth.configuration.user_type.constantize, null: true

  def resolve(email:, password:, remember_me:, google_authenticator_code:)
    response = context[:response]
    request = context[:request]

    if lockable?
      user = User.where(locked_at: nil).find_by email: email
    else
      user = User.find_by email: email
    end
    
    error_message = nil

    valid_sign_in = user.present? && user.valid_password?(password)
    
    if user.present? && !user.valid_password?(password)
      error_message = I18n.t('devise.failure.invalid',
                                authentication_keys: I18n.t('activerecord.attributes.user.email', default: 'email'))
    end
    
    if valid_sign_in && GraphQL::Auth.configuration.enable_google_authenticator_tfa
      valid_sign_in = verify_google_code(user, google_authenticator_code)
      if !valid_sign_in
        error_message = 'Google Authenticator code is not valid'
      end
    end

    if valid_sign_in
      generate_access_token(user, response)
      set_current_user(user)
      devise_sign_in(user)
      remember_me ? set_refresh_token(user, response) : delete_refresh_token(user)

      {
        errors: [],
        success: true,
        user: user
      }
    else
      if error_message.present?
        devise_failure(user.email, error_message)
      end
      {
        errors: [
          {
            field: :_error,
                message: error_message
          }
        ],
        success: false,
        user: nil
      }
    end
  end
end
