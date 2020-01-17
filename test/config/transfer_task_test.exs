# Pleroma: A lightweight social networking server
# Copyright © 2017-2019 Pleroma Authors <https://pleroma.social/>
# SPDX-License-Identifier: AGPL-3.0-only

defmodule Pleroma.Config.TransferTaskTest do
  use Pleroma.DataCase

  alias Pleroma.ConfigDB

  clear_config(:configurable_from_database) do
    Pleroma.Config.put(:configurable_from_database, true)
  end

  test "transfer config values from db to env" do
    refute Application.get_env(:pleroma, :test_key)
    refute Application.get_env(:idna, :test_key)
    refute Application.get_env(:quack, :test_key)

    ConfigDB.create(%{
      group: ":pleroma",
      key: ":test_key",
      value: [live: 2, com: 3]
    })

    ConfigDB.create(%{
      group: ":idna",
      key: ":test_key",
      value: [live: 15, com: 35]
    })

    ConfigDB.create(%{
      group: ":quack",
      key: ":test_key",
      value: [:test_value1, :test_value2]
    })

    Pleroma.Config.TransferTask.start_link([])

    assert Application.get_env(:pleroma, :test_key) == [live: 2, com: 3]
    assert Application.get_env(:idna, :test_key) == [live: 15, com: 35]
    assert Application.get_env(:quack, :test_key) == [:test_value1, :test_value2]

    on_exit(fn ->
      Application.delete_env(:pleroma, :test_key)
      Application.delete_env(:idna, :test_key)
      Application.delete_env(:quack, :test_key)
    end)
  end

  test "transfer config values for 1 group and some keys" do
    level = Application.get_env(:quack, :level)
    meta = Application.get_env(:quack, :meta)

    ConfigDB.create(%{
      group: ":quack",
      key: ":level",
      value: :info
    })

    ConfigDB.create(%{
      group: ":quack",
      key: ":meta",
      value: [:none]
    })

    Pleroma.Config.TransferTask.start_link([])

    assert Application.get_env(:quack, :level) == :info
    assert Application.get_env(:quack, :meta) == [:none]
    default = Pleroma.Config.Holder.config(:quack, :webhook_url)
    assert Application.get_env(:quack, :webhook_url) == default

    on_exit(fn ->
      Application.put_env(:quack, :level, level)
      Application.put_env(:quack, :meta, meta)
    end)
  end

  test "non existing atom" do
    ConfigDB.create(%{
      group: ":pleroma",
      key: ":undefined_atom_key",
      value: [live: 2, com: 3]
    })

    assert ExUnit.CaptureLog.capture_log(fn ->
             Pleroma.Config.TransferTask.start_link([])
           end) =~
             "updating env causes error, key: \":undefined_atom_key\", error: %ArgumentError{message: \"argument error\"}"
  end
end
