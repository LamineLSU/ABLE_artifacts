rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF }  // Includes preceding instructions for context
        $pattern1 = { FF 75 08 FF 15 AC B0 41 00 } //Focus on the memory call
        $pattern2 = { 8B FF 55 8B EC FF 75 08 } //Includes preceding instructions for context

    condition:
        any of them
}