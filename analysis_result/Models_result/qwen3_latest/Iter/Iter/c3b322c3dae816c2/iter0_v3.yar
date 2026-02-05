rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific test and call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? }  // Test EAX and short jump
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test EAX and near jump
        $pattern2 = { FF 15 ?? ?? ?? ?? }  // Call to ExitProcess

    condition:
        any of them
}