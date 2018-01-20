defmodule Exbtc.BIP32Test do
  use ExUnit.Case
  alias Exbtc.BIP32, as: BIP32

  test "electrum_mpk should work" do
    seed = "9c15039d28b7049b02db5e31a6c40468"

    assert BIP32.electrum_mpk(seed) ==
             "38446fac3bf69e9d463aa0917048fe09b2cb1869fc586acec76169a6d0153b5d1401ba450685bbe2cc4380aab65e0a9dac18a8022f324a11b37b43d2c35fa5bb"
  end

  @seed "5d86a4052f41170c6961ed0cc9af8bcf"

  test "electrum_privkey case 0" do
    assert BIP32.electrum_privkey(@seed, 1) ==
             "a1041383546ced230636c8cbb933bfa6912a73d89cdc08d99d69109395318dbc"
  end

  test "electrum_privkey case 1" do
    assert BIP32.electrum_privkey(@seed, 100, 1) ==
             "c528d5e7c9ea431c5c2cde63d84bfc49b3abb5ef80f9375ca5412d613dc1f17c"
  end

  test "electrum_pubkey case 0" do
    assert BIP32.electrum_pubkey(@seed, 1) ==
             "040cd8f9cb452bf402237ac4074644cd43fa75ea3f32a853be04102e139559818b7f28dfcecd29ef4b985c2c8920f534e4fa3b181c8325443b8c01c7d6b16b45e5"
  end

  test "electrum_address " do
    assert BIP32.electrum_address(@seed, 3) == "1HuVyb4YBuX6YezM2vVMwHgyYHC88je3t6"
  end

  test "bip32_master_key" do
    seed = "21456t243rhgtucyadh3wgyrcubw3grydfbng"

    assert BIP32.bip32_master_key(seed) ==
             "xprv9s21ZrQH143K2napkeoHT48gWmoJa89KCQj4nqLfdGybyWHP9Z8jvCGzuEDv4ihCyoed7RFPNbc9NxoSF7cAvH9AaNSvepUaeqbSpJZ4rbT"
  end

  test "bip32_extract_key" do
    key =
      "xprv9s21ZrQH143K2napkeoHT48gWmoJa89KCQj4nqLfdGybyWHP9Z8jvCGzuEDv4ihCyoed7RFPNbc9NxoSF7cAvH9AaNSvepUaeqbSpJZ4rbT"

    assert BIP32.bip32_extract_key(key) ==
             "7095a63c925622891fbb0152710d7c5abb5516d973222391351e53241989aa6001"
  end

  @seed "000102030405060708090a0b0c0d0e0f"

  test "bip32_ckd child key derivation case 0" do
    key = master_key(@seed)

    assert BIP32.bip32_ckd(key, 0) ==
             "xprv9vP5sMbLg72gDgrnsmfqesSgHPptciMYYyz3d3sUFV7hJeuioLevaqfr5DZzT4rpfCnNCzvLkeRTHuNrHJWFy83YA4PZM2ysPM2mAdTKB5o"
  end

  test "bip32_ckd child key derivation case 1" do
    key = master_key(@seed)

    assert BIP32.bip32_ckd(key, 10) ==
             "xprv9vP5sMbLg72gdkusoZZL5mnxxMTb9Gjj36myc3zhzkKZjcSXJ6gxApYTVkSkLMzb6Up4pyoV2GZCQexMNEjT6soiBGG5D7XrER2zwM7gHfe"
  end

  test "bip32_privtopub" do
    key = master_key(@seed)

    assert BIP32.bip32_privtopub(key) ==
             "xpub661MyMwAqRbcGSMdR8QTQqz22hBvK8DS3MmanH6ZeE5RJ84YndJ59aUXvSg3R8z7o4GwP7CgAYRhZmDdTGXejEX3QVy4vC2k1fFjbUgsCud"
  end

  def master_key(seed) do
    BIP32.bip32_master_key(seed)
  end
end
