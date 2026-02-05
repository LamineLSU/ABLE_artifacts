rule Bypass_Sample
{
    meta:
        description = "Detects obfuscated call sequences with displacement wildcards"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 51 FF D2 8B 45 ?? }
        $pattern1 = { 52 FF D0 8B 45 ?? }
        $pattern2 = { 8B 45 ?? 51 FF D2 }

    condition:
        any of them
}