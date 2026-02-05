rule EvasionCheck
{
    meta:
        description = "Detects evasion checks involving calls to ExitProcess and other anti-debugging checks."
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Analyst"

    strings:
        $a = { 50 E8 ?? ?? ?? ?? 8B 06 83 C4 14 85 C0 0F 84 ?? ?? ?? ?? }
        $b = { 52 FF D0 5E 5D C3 }
        $c = { 8B 06 83 C4 14 E8 ?? ?? ?? ?? }

    condition:
        all of ($a, $b, $c)
}