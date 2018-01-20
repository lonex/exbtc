defmodule Exbtc.Api do
  use HTTPoison.Base

  @blockchain_info_host "https://blockchain.info"

  def fetchtx(txhash) when is_list(txhash) do
    Enum.map(txhash, &fetchtx(&1))
  end

  def fetchtx(txhash) do
    case get("#{@blockchain_info_host}/rawtx/#{txhash}?format=hex") do
      {:ok, %HTTPoison.Response{body: body, status_code: status}} when status in 200..299 ->
        body

      {:ok, %HTTPoison.Response{body: body}} ->
        raise "Request returned non-200 response. Error: #{body}"

      {:error, error} ->
        raise "fetchtx error: #{error}"
    end
  end

  def unspent(address) do
    address_unspent(address)
    |> Enum.reduce([], fn o_map, acc ->
      acc ++
        [
          %{
            "output" =>
              Map.get(o_map, "tx_hash") <> ":" <> to_string(Map.get(o_map, "tx_output_n")),
            "value" => Map.get(o_map, "value")
          }
        ]
    end)
  end

  def address_unspent(address) do
    url = "#{@blockchain_info_host}/unspent?active=#{address}"

    case get(url) do
      {:ok, %HTTPoison.Response{body: body, status_code: status}} when status in 200..299 ->
        case Poison.decode(body) do
          {:ok, %{"unspent_outputs" => outputs}} ->
            outputs

          _ ->
            raise "Fetch address history error"
        end

      {:ok, %HTTPoison.Response{body: body}} ->
        raise "Request returned non-200 response. Error: #{body}"

      {:error, error} ->
        raise "Fetch address history error: #{error}"
    end
  end

  @doc """
  e.g. 
  [
    %{"address" => "1Cdid9KFAaatwczBwBttQcwXYCpvK8h7FK", 
      "block_height" => 277298,
      "output" => "7957a35fe64f80d234d76d83a2a8f1a0d8149a41d81de548f0a65a8a999f6f18:0",
      "spent" => "0627052b6f28912f2703066a912ea577f2ce4da4caa5a5fbd8a57286c345c2f2:0",
      "value" => 10000000},
  ]
  """
  @spec history(String.t()) :: %{String.t() => any}
  def history(address) do
    txs = address_transactions(address)

    Enum.reduce(txs, history_outs(txs, address), fn tx, outs ->
      inputs = Map.get(tx, "inputs")

      Enum.zip(inputs, 0..(length(inputs) - 1))
      |> Enum.reduce(outs, fn {input, index}, sub_outs ->
        if Map.has_key?(input, "prev_out") and address == get_in(input, ["prev_out", "addr"]) do
          key =
            to_string(get_in(input, ["prev_out", "tx_index"])) <>
              ":" <> to_string(get_in(input, ["prev_out", "n"]))

          if Map.has_key?(sub_outs, key) do
            put_in(sub_outs, [key, "spent"], Map.get(tx, "hash") <> ":" <> to_string(index))
          else
            sub_outs
          end
        else
          sub_outs
        end
      end)
    end)
    |> Map.values()
    |> Enum.sort(&(Map.get(&1, "block_height") < Map.get(&2, "block_height")))
  end

  defp history_outs(txs, address) do
    Enum.reduce(txs, %{}, fn tx, final_outs ->
      Enum.reduce(Map.get(tx, "out", []), final_outs, fn output, outs ->
        if address == Map.get(output, "addr") do
          key = to_string(Map.get(tx, "tx_index")) <> ":" <> to_string(Map.get(output, "n"))

          Map.put(outs, key, %{
            "address" => Map.get(output, "addr"),
            "value" => Map.get(output, "value"),
            "output" => Map.get(tx, "hash", "") <> ":" <> to_string(Map.get(output, "n")),
            "block_height" => Map.get(tx, "block_height", nil)
          })
        else
          outs
        end
      end)
    end)
  end

  @page_size 50

  def address_transactions(address, offset \\ 0, transactions \\ []) do
    url = "#{@blockchain_info_host}/address/#{address}?format=json&offset=#{offset}"

    case get(url) do
      {:ok, %HTTPoison.Response{body: body, status_code: status}} when status in 200..299 ->
        case Poison.decode(body) do
          {:ok, %{"address" => _, "txs" => txs}} ->
            if length(txs) >= @page_size do
              IO.puts("Fetching next page of transactions, offset #{offset + @page_size}")
              address_transactions(address, offset + @page_size, transactions ++ txs)
            else
              transactions ++ txs
            end

          _ ->
            raise "Fetch address history error"
        end

      {:ok, %HTTPoison.Response{body: body}} ->
        raise "Request returned non-200 response. Error: #{body}"

      {:error, error} ->
        raise "Fetch address history error: #{error}"
    end
  end
end
