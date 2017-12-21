defmodule Exbtc.BIP32Test do
  use ExUnit.Case
  alias Exbtc.BIP32, as: BIP32

  test "electrum_mpk should work" do
    seed = "9c15039d28b7049b02db5e31a6c40468"
    assert BIP32.electrum_mpk(seed) == "38446fac3bf69e9d463aa0917048fe09b2cb1869fc586acec76169a6d0153b5d1401ba450685bbe2cc4380aab65e0a9dac18a8022f324a11b37b43d2c35fa5bb"
  end

  @seed "5d86a4052f41170c6961ed0cc9af8bcf"

  test "electrum_privkey case 0" do
    assert BIP32.electrum_privkey(@seed, 1) == "a1041383546ced230636c8cbb933bfa6912a73d89cdc08d99d69109395318dbc"
  end

  test "electrum_privkey case 1" do
    assert BIP32.electrum_privkey(@seed, 100, 1) == "c528d5e7c9ea431c5c2cde63d84bfc49b3abb5ef80f9375ca5412d613dc1f17c"
  end

  test "electrum_pubkey case 0" do
    assert BIP32.electrum_pubkey(@seed, 1) == "040cd8f9cb452bf402237ac4074644cd43fa75ea3f32a853be04102e139559818b7f28dfcecd29ef4b985c2c8920f534e4fa3b181c8325443b8c01c7d6b16b45e5"
  end

  test "electrum_address " do
    assert BIP32.electrum_address(@seed, 3) == "1HuVyb4YBuX6YezM2vVMwHgyYHC88je3t6"
  end
end