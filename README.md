# Exbtc

This project has a set of ECC utils that are ported from the [Pybitcointools](https://github.com/vbuterin/pybitcointools). The port is complete over the core functions, but lacks the transaction and electrum utils.

## Example usage in IEx

Key encoding and decoding

```elixir
iex(1)> alias Exbtc.Core, as: BtcCore
Exbtc.Core
iex(2)> private_key_hex = "3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6"
"3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6"
iex(3)> decoded_private_key = BtcCore.decode_privkey(private_key_hex)
26563230048437957592232553826663696440606756685920117476832299673293013768870
iex(4)> private_key = BtcCore.decode_privkey(private_key_hex)
26563230048437957592232553826663696440606756685920117476832299673293013768870
iex(5)> private_key_wif = BtcCore.encode_privkey(private_key, "wif")
"5JG9hT3beGTJuUAmCQEmNaxAuMacCTfXuw1R3FCXig23RQHMr4K"
iex(6)> private_key_wif_compressed = BtcCore.encode_privkey(private_key, "wif_compressed")
"KyBsPXxTuVD82av65KZkrGrWi5qLMah5SdNq6uftawDbgKa2wv6S"
iex(7)> private_key_hex_compressed = BtcCore.encode_privkey(private_key, "hex_compressed")
"3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa601"
iex(8)> pub_key = BtcCore.privkey_to_pubkey(private_key)
{41637322786646325214887832269588396900663353932545912953362782457239403430124,
 16388935128781238405526710466724741593761085120864331449066658622400339362166}
iex(9)> pub_key = BtcCore.privkey_to_address(private_key)
"1thMirt546nngXqyPEz532S8fLwbozud8"
iex(10)> pub_key = BtcCore.privkey_to_pubkey(private_key_wif)
"045c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec243bcefdd4347074d44bd7356d6a53c495737dd96295e2a9374bf5f02ebfc176"
iex(11)> BtcCore.pubkey_to_address(pub_key)
"1thMirt546nngXqyPEz532S8fLwbozud8"
```

ECDSA

```elixir
iex(2)> alias Exbtc.Core, as: BtcCore
Exbtc.Core
iex(3)> priv_key = BtcCore.random_key()
"5697fc127aec13cf59f971c3acac154e6f949468a7b45be555c7068b333907c9"
iex(4)> pub_key = BtcCore.privkey_to_pubkey(priv_key)
"040037c95bae0ecd368d0b9dcc47f0f6d17c008443be3c77dfc62af7b49b8271d22fb6d302519c550cffd69e5922f7408ae00d3cc0051021efaa8c814a596c6315"
iex(5)> msg = "hello world!"
"hello world!"
iex(6)> signature = BtcCore.ecdsa_sign(msg, priv_key)
"G4Xf2Y5mozpgPGua1KHqeCUeNFjhmFn6NOlanC+X0l/vFDxKYy3oz/So4F6BPmjMDitjrOAKt3dtlEJa5G9+Kbo="
iex(7)> address = BtcCore.privkey_to_address(priv_key)
"1Q44VRuHh1eK6eSjXL4cr6FuZE6SNHM3th"
iex(8)> BtcCore.ecdsa_verify(msg, signature, address)
true
iex(9)> BtcCore.ecdsa_verify(msg, signature, pub_key)
true
```

For more usage, please refer to the test cases in [test/core_test.exs](https://github.com/lonex/exbtc/blob/master/test/core_test.exs).

## Example usage for your project

```elixir
# mix.exs
defmodule ExbtcEg.Mixfile do
  use Mix.Project

  def project do
    [
      app: :exbtc_eg,
      version: "0.1.0",
      elixir: "~> 1.5",
      start_permanent: Mix.env == :prod,
      deps: deps()
    ]
  end

  # ...
  defp deps do
    [
      { :exbtc, "~> 0.1.0" }
    ]
  end
end
```

In the application code somewhere, e.g. `lib/ExbtcEg.ex`

```elixir
defmodule ExbtcEg do
  alias Exbtc.Core, as: ExbtcCore

  def hello do
    p1 = "14ba671a90d51bbe75fe23f4e91bd63ced567adf68e9802fb16d7cbfca1f5f05"
    msg = "it is cool"
    sig = ExbtcCore.ecdsa_sign(msg, p1)
  end
end
```

## Installation

The package can be installed by adding `exbtc` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:exbtc, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/exbtc](https://hexdocs.pm/exbtc).

