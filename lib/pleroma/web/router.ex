defmodule Pleroma.Web.Router do
  use Pleroma.Web, :router

  alias Pleroma.{Repo, User}

  def user_fetcher(username) do
    {:ok, Repo.get_by(User, %{nickname: username})}
  end

  pipeline :api do
    plug :accepts, ["json"]
    plug :fetch_session
    plug Pleroma.Plugs.AuthenticationPlug, %{fetcher: &Pleroma.Web.Router.user_fetcher/1, optional: true}
  end

  pipeline :authenticated_api do
    plug :accepts, ["json"]
    plug :fetch_session
    plug Pleroma.Plugs.AuthenticationPlug, %{fetcher: &Pleroma.Web.Router.user_fetcher/1}
  end

  scope "/api", Pleroma.Web do
    pipe_through :api
    get "/statuses/public_timeline", TwitterAPI.Controller, :public_timeline
    get "/statuses/public_and_external_timeline", TwitterAPI.Controller, :public_timeline
    get "/statuses/show/:id", TwitterAPI.Controller, :fetch_status
    get "/statusnet/conversation/:id", TwitterAPI.Controller, :fetch_conversation
  end

  scope "/api", Pleroma.Web do
    pipe_through :authenticated_api

    post "/account/verify_credentials", TwitterAPI.Controller, :verify_credentials
    post "/statuses/update", TwitterAPI.Controller, :status_update
    get "/statuses/friends_timeline", TwitterAPI.Controller, :friends_timeline
    post "/friendships/create", TwitterAPI.Controller, :follow
    post "/friendships/destroy", TwitterAPI.Controller, :unfollow
    post "/statusnet/media/upload", TwitterAPI.Controller, :upload
  end
end