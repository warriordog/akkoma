# Pleroma: A lightweight social networking server
# Copyright © 2017-2020 Pleroma Authors <https://pleroma.social/>
# SPDX-License-Identifier: AGPL-3.0-only

defmodule Pleroma.Web.ApiSpec.AccountOperationTest do
  use Pleroma.Web.ConnCase, async: true

  alias Pleroma.Web.ApiSpec
  alias Pleroma.Web.ApiSpec.Schemas.Account
  alias Pleroma.Web.ApiSpec.Schemas.AccountCreateRequest
  alias Pleroma.Web.ApiSpec.Schemas.AccountCreateResponse
  alias Pleroma.Web.ApiSpec.Schemas.AccountUpdateCredentialsRequest

  import OpenApiSpex.TestAssertions
  import Pleroma.Factory

  test "Account example matches schema" do
    api_spec = ApiSpec.spec()
    schema = Account.schema()
    assert_schema(schema.example, "Account", api_spec)
  end

  test "AccountCreateRequest example matches schema" do
    api_spec = ApiSpec.spec()
    schema = AccountCreateRequest.schema()
    assert_schema(schema.example, "AccountCreateRequest", api_spec)
  end

  test "AccountCreateResponse example matches schema" do
    api_spec = ApiSpec.spec()
    schema = AccountCreateResponse.schema()
    assert_schema(schema.example, "AccountCreateResponse", api_spec)
  end

  test "AccountUpdateCredentialsRequest example matches schema" do
    api_spec = ApiSpec.spec()
    schema = AccountUpdateCredentialsRequest.schema()
    assert_schema(schema.example, "AccountUpdateCredentialsRequest", api_spec)
  end

  test "AccountController produces a AccountCreateResponse", %{conn: conn} do
    api_spec = ApiSpec.spec()
    app_token = insert(:oauth_token, user: nil)

    json =
      conn
      |> put_req_header("authorization", "Bearer " <> app_token.token)
      |> put_req_header("content-type", "application/json")
      |> post(
        "/api/v1/accounts",
        %{
          username: "foo",
          email: "bar@example.org",
          password: "qwerty",
          agreement: true
        }
      )
      |> json_response(200)

    assert_schema(json, "AccountCreateResponse", api_spec)
  end

  test "AccountUpdateCredentialsRequest produces an Account", %{conn: conn} do
    api_spec = ApiSpec.spec()
    token = insert(:oauth_token, scopes: ["read", "write"])

    json =
      conn
      |> put_req_header("authorization", "Bearer " <> token.token)
      |> put_req_header("content-type", "application/json")
      |> patch(
        "/api/v1/accounts/update_credentials",
        %{
          hide_followers_count: "true",
          hide_follows_count: "true",
          skip_thread_containment: "true",
          hide_follows: "true",
          pleroma_settings_store: %{"pleroma-fe" => %{"key" => "val"}},
          note: "foobar",
          fields_attributes: [%{name: "foo", value: "bar"}]
        }
      )
      |> json_response(200)

    assert_schema(json, "Account", api_spec)
  end
end
