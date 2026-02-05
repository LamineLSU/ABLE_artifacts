rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern+0,action0=skip,count=1"

    strings:
        $pattern = { FF ?? D2 ?? ?? 01 }

    condition:
        any of them
}