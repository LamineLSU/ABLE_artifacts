rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - focuses on early check"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip"

    strings:
        $pattern0 = { 8B 40 68 ?? ?? ?? ?? 74 20 } // Early call and conditional EAX check
        $pattern1 = { FF 75 08 ?? FF 15 40 70 2D 01 C1 E8 } // Conditional exit decision point

    condition:
        any of them
}