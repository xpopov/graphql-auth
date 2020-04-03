module GraphQL
  module Auth
    class Engine < ::Rails::Engine
      # isolate_namespace GraphQL::Auth

      config.autoload_paths += Dir["#{config.root}/app/graphql"]
      # config.autoload_paths += Dir["#{config.root}/app/**/"]

      # initializer "graph_q_l_auth.add_middleware" do |app|
      #   app.middleware.use GraphQL::Auth::Middleware
      # end
    end
  end
end
