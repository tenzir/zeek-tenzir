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
