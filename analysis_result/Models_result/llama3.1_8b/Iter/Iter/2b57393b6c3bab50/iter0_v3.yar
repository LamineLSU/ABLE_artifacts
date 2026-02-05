rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:

    condition:
        any of them
}

strings:

$pattern0 = { E8 ?? ?? ?? ?? ?? ?? ?? ?? 57 8D 4D E8 }
$pattern1 = { 8D 8D 40 FF FF FF E8 48 C2 FE FF 8D 8D 58 FF FF FF }
$pattern2 = { 5F 5E 8B E5 C2 10 00 }