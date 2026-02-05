rule Bypass_Sample
{
    meta:
        description: "Evasion bypass rule targeting specific call sequences"
        cape_options: "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF7508 E8C8FFFFFF 59 }  # Targeting the first call with surrounding context
        $pattern1 = { 5B FF7508 E8C8FFFFFF 5A 8B }  # Including known instructions before and after the call
        $pattern2 = { FF7508 E8C8FFFFFF ?? }  # Using wildcard for unknown subsequent instruction

    condition:
        any of them
}