defmodule Ueberauth.Strategy.Okta.Client do

  require Jason
  require Logger
  alias OAuth2.{AccessToken, Request}
  alias OAuth2.Client, as: OAuth2Client

  def get_token(%{token_method: method} = client, params \\ [], headers \\ [], opts \\ []) do
    {client, url} = token_url(client, params, headers)
    Logger.debug("Strategy.Okta.Client.get_token:")
    Logger.debug("client = "<>inspect(client, pretty: true))
    Logger.debug("params = "<>inspect(client.params, pretty: true))
    Logger.debug("headers = "<>inspect(client.headers, pretty: true))

    case Request.request(method, client, url, client.params, client.headers, opts) do
      {:ok, response} ->
        token = extract_token(response.body) |> AccessToken.new
        {:ok, %{client | headers: [], params: %{}, token: token}}

      {:error, error} ->
        {:error, error}
    end
  end

  defp extract_token(response_body) when is_binary(response_body), do: Jason.decode!(response_body)
  defp extract_token(response_body), do: response_body

  # Cribbed from OAuth2.Client as they are private and we must redeclare them here in our re-implementation

  defp token_post_header(%{token_method: :post} = client),
    do: OAuth2Client.put_header(client, "content-type", "application/x-www-form-urlencoded")

  defp token_url(client, params, headers) do
    client
    |> token_post_header()
    |> client.strategy.get_token(params, headers)
    |> to_url(:token_url)
  end

  defp to_url(client, endpoint) do
    {client, Map.get(client, endpoint) <> "?" <> URI.encode_query(client.params)}
  end
end
