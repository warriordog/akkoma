# ---------------------------------------
# TODO: add include / exclude regex
# ---------------------------------------

defmodule Pleroma.Web.ActivityPub.MRF.SuspiciousMentionsPolicy do
  @moduledoc "Filter activities that contain suspicious mentions (no follow relations, media only, mass DMs, etc)."

  @behaviour Pleroma.Web.ActivityPub.MRF.Policy

  require Pleroma.Constants

  alias Pleroma.Config
  alias Pleroma.User

  # Based on hellthread_policy.ex
  defp count_mentions(message, %User{:follower_address => followers}) do
    recipients = (message["to"] || []) ++ (message["cc"] || [])

    recipients
    |> List.delete(followers)
    |> List.delete(Pleroma.Constants.as_public())
    |> length()
  end

  defp count_attachments(attachments) do
    if is_list(attachments) do
      length(attachments)
    else
      0
    end
  end

  # Based on anti_link_spam_policy.ex
  defp count_links(content) do
    content
    |> Floki.parse_fragment!()
    |> Floki.filter_out("a.mention,a.hashtag,a[rel~=\"tag\"],a.zrl")
    |> Floki.attribute("a", "href")
    |> length()
  end

  # Catch messages which match the mention / attachment threshold, then filter based on the follow / char count thresholds.
  # Reject whatever is left.
  @impl true
  def filter(%{"type" => activity_type, "actor" => actor, "object" => %{"attachment" => attachments, "content" => content}} = message)
      when activity_type in ~w{Create Update}
  do
    {:ok, %User{local: false} = user} = User.get_or_fetch_by_ap_id(actor)

    # Get MRF configuration
    minimum_mentions = Pleroma.Config.get([:mrf_suspicious_mentions, :minimum_mentions])
    minimum_attachments = Pleroma.Config.get([:mrf_suspicious_mentions, :minimum_attachments])
    minimum_links = Pleroma.Config.get([:mrf_suspicious_mentions, :minimum_links])
    # maximum_followers = Pleroma.Config.get([:mrf_suspicious_mentions, :maximum_followers])
    # maximum_followees = Pleroma.Config.get([:mrf_suspicious_mentions, :maximum_followees])
    maximum_char_count = Pleroma.Config.get([:mrf_suspicious_mentions, :maximum_char_count])
    maximum_user_notes = Pleroma.Config.get([:mrf_suspicious_mentions, :maximum_user_notes])
    maximum_user_followers = Pleroma.Config.get([:mrf_suspicious_mentions, :maximum_user_followers])

    # Calculate metadata
    mentions = count_mentions(message, user)
    attachments = count_attachments(attachments)
    links = count_links(content)
    # followers = count_followers()
    # followees =
    characters = String.length(content)
    user_notes = user.note_count
    user_followers = user.follower_count

    # Verify the message
    cond do
      # Allow messages that don't meet the mention threshold
      mentions < minimum_mentions
        -> {:ok, message}

      # Allow messages that don't meet the flag thresholds (attachments or links)
      attachments < minimum_attachments && links < minimum_links
        -> {:ok, message}

      # # Allow messages that *do* meet the followers threshold
      # mentions < maximum_followers
      #   -> {:ok, object}

      # # Allow messages that *do* meet the followees threshold
      # mentions < maximum_followees
      #   -> {:ok, object}

      # Allow messages that meet the character count threshold
      mentions > maximum_char_count
        -> {:ok, message}

      # Allow messages from users that meet the notes threshold
      user_notes > maximum_user_notes
        -> {:ok, message}

      # Allow messages from users that meet the followers threshold
      user_followers > maximum_user_followers
        -> {:ok, message}

      # Remaining messages have failed all checks and should be rejected
      true
        # followers=#{followers}, followees=#{followees},
        -> {:reject, "[SuspiciousMentionsPolicy] rejected message: mentions=#{mentions}, attachments=#{attachments}, links=#{links}, characters=#{characters}, user_notes=#{user_notes}, user_follows=#{user_followers}"}
    end
  end

  # Fallback
  @impl true
  def filter(message), do: {:ok, message}

  @impl true
  def describe,
    do: {:ok, %{mrf_suspicious_mentions: Config.get(:mrf_suspicious_mentions) |> Map.new()}}

  @impl true
  def config_description do
    %{
      key: :mrf_suspicious_mentions,
      related_policy: "Pleroma.Web.ActivityPub.MRF.SuspiciousMentionsPolicy",
      label: "MRF Suspicious Mentions",
      description: "Filter activities with multiple mentions. Activities are rejected if they meet a mention threshold and exceed either a link or attachment threshold. Additional options are available to tune the MRF and reduce false-positives.",
      children: [
        %{
          key: :minimum_mentions,
          label: "Minimum mentions",
          type: :integer,
          description: "MRF will reject activities with at least this many mentions, as long as it has enough attachments or links.",
          suggestions: [1, 5, 10]
        },
        %{
          key: :minimum_attachments,
          label: "Minimum attachments",
          type: :integer,
          description: "MRF will flag activities with at least this many media attachments.",
          suggestions: [0, 1]
        },
        %{
          key: :minimum_links,
          label: "Minimum links",
          type: :integer,
          description: "MRF will flag activities with at least this many links.",
          suggestions: [0, 1]
        },
        # %{
        #   key: :maximum_followers,
        #   label: "Maximum remote followers",
        #   type: :integer,
        #   description: "MRF will allow activities from instances with more than this many users following our instance.",
        #   suggestions: [0, 1, 2, 5]
        # },
        # %{
        #   key: :maximum_followees,
        #   label: "Maximum local followees",
        #   type: :integer,
        #   description: "MRF will allow activities from instances with more than this many users followed by our instance.",
        #   suggestions: [0, 1, 2, 5]
        # },
        %{
          key: :maximum_char_count,
          label: "Maximum character count",
          type: :integer,
          description: "MRF will allow activities with more than this many characters of text (excluding mentions and links).",
          suggestions: [0, 1, 5, 10]
        },
        %{
          key: :maximum_user_notes,
          label: "Maximum notes by author",
          type: :integer,
          description: "MRF will allow activities from users with more than this many previous posts.",
          suggestions: [0, 1, 5, 10]
        },
        %{
          key: :maximum_user_followers,
          label: "Maximum followers",
          type: :integer,
          description: "MRF will allow activities from users with more than this many followers.",
          suggestions: [0, 1, 5, 10]
        }
      ]
    }
  end
end
