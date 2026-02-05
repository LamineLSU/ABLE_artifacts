rule Evasion_Bypass
{
    meta:
        description = "Detects evasion checks and ExitProcess calls"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Security Analyst"
    strings:
        $a = { 85 C0 74 12 ?? ?? } // test eax, eax + je (first occurrence)
        $b = { 85 C0 0F 84 ?? ?? ?? ?? } // test eax, eax + je (second occurrence)
        $c = { FF 15 ?? ?? ?? ?? } // ExitProcess call
    condition:
        all of ($a, $b, $c)
}