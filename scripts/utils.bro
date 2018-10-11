## Generates a random 16-byte UUID.
##
## Returns: A random UUID, e.g., ``6ef0cb1a-f0b2-44d7-9303-6000091e35e3``.
function random_uuid() : string
  {
  # We use the 11 bytes of unique_id() with a fixed 5-byte prefix to end up
  # with 16 bytes for the UUID.
  local uid = unique_id("VAST-");
  # unique_id() doesn't always return 11 bytes! In this case the result needs
  # to padded/trimmed.
  if ( |uid| < 16 )
    while ( |uid| < 16 )
      uid = cat(uid, "-");
  else if ( |uid| > 16 )
    uid = sub_bytes(uid, 0, 16);
  return uuid_to_string(uid);
  }

function secs(x: double): count
	{
	return double_to_count(x);
	}

function mins(x: double): count
	{
	return secs(x) / 60;
	}

function hours(x: double): count
	{
	return mins(x) / 60;
	}

function days(x: double): count
	{
	return hours(x) / 24;
	}

function months(x: double): count
	{
	return days(x) / 30;
	}

function years(x: double): count
	{
	return days(x) / 365;
	}

function deconstruct(x: interval): string
	{
	local result = "";
	local d = interval_to_double(x);
	local num_years = years(d);
	if ( num_years > 0 )
		{
		result += cat(num_years) + "y";
		d -= num_years * 365 * 24 * 60 * 60;
		}
	local num_months = months(d);
	if ( num_months > 0 )
		{
		result += cat(num_months) + "M";
		d -= num_months * 30 * 24 * 60 * 60;
		}
	local num_days = days(d);
	if ( num_days > 0 )
		{
		result += cat(num_days) + "d";
		d -= num_days * 24 * 60 * 60;
		}
	local num_hours = hours(d);
	if ( num_hours > 0 )
		{
		result += cat(num_hours) + "h";
		d -= num_hours * 60 * 60;
		}
	local num_mins = mins(d);
	if ( num_mins > 0 )
		{
		result += cat(num_mins) + "m";
		d -= num_mins * 60;
		}
	local num_secs = secs(d);
	if ( num_secs > 0 )
		{
		result += cat(num_secs) + "s";
		d -= num_secs * 60;
		}
	return result;
	}
