rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting specific decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 75 08 C0 0F 84 FF EC }  // TEST EAX followed by JE/JNE
        $pattern1 = { 8B EC F8 01 74 12 8B 4D F8 }    // Specific conditional checks before ExitProcess
        $pattern2 = { C3 FF C9 85 D6 DD 0C 0F FF }   // Alternative bypass path with flags

    condition:
        any of them
}