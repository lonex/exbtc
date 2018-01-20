defmodule Exbtc.Mixfile do
  use Mix.Project

  def project do
    [
      app: :exbtc,
      description:
        "Elixir ECC (Elliptic curve cryptography) utils, port from Python Bitcoin tool (https://github.com/vbuterin/pybitcointools)",
      package: package(),
      version: "0.1.3",
      elixir: "~> 1.5",
      # build_embedded: Mix.env == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, ">= 0.0.0", only: :dev},
      {:httpoison, ">= 0.9.0"},
      {:poison, ">= 2.2.0"}
    ]
  end

  defp package do
    [
      maintainers: ["lonex"],
      licenses: ["MIT"],
      links: %{github: "https://github.com/lonex/exbtc"},
      files: ~w(lib mix.exs README.md)
    ]
  end
end
