defmodule Exbtc.UTest do
  use ExUnit.Case
  alias Exbtc.C, as: C
  alias Exbtc.U, as: U

  test "power function work for big ints" do
  	assert U.power(
  		32670510020758816978083085130507043184471273380659243275938904335757337482424, 
  		28948022309329048855892746252171976963317496166410141009864396001977208667916, 
  		C.p()) == 65905178935660155284462022142075717170485136974784532884405716975433538830339
  end

  test "power function raise error on negative power" do
  	assert_raise FunctionClauseError, ~r/no function clause matching in Exbtc.U.power/, fn -> U.power(2, -1, 2) end
  end
end