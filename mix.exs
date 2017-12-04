defmodule Exbtc.Mixfile do
  use Mix.Project

  def project do
    [
      app: :exbtc,
      description: "Bitcoin Exlixir port",
      package: package(),
      version: "0.1.0",
      elixir: "~> 1.5",
      # build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
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
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"},
    ]
  end

  defp package do
    [
      contributors: [ "lonex" ],
      licenses: [ "MIT" ],
      links: %{github: "https://github.com/lonex/exbt"},
      files: ~w(lib mix.exs, README.md)
    ]
  end
end
