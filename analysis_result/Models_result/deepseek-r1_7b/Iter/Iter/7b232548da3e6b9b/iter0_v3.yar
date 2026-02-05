rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting TEST EAX, unknown call, and initial setup"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? 4F ?? ?? 8B 4C ?? }   // TEST EAX and JZ/JE bypass
        $pattern1 = { FF 75 08 ?? 6A 09 FF 15 AC B0 41 00 } // Unknown call bypass
        $pattern2 = { 55 ?? 8B EC ?? FF 75 08 ?? }       // Initial setup bypass
    condition:
        any of them
}