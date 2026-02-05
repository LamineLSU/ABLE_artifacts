rule ObservedCallSequence
{
    meta:
        description = "Detects a specific call sequence observed in memory dump"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        confidence = 100

    strings:
        $pattern0 = { E8 C8 FF FF FF 59 }  // Call to ___crtCorExitProcess followed by pop ecx
        $pattern1 = { FF 75 08 FF 15 AC B0 41 00 }  // Push ebp+8 followed by call to ExitProcess
        $pattern2 = { FF 15 AC B0 41 00 }  // Call to ExitProcess at address 0041B0AC

    condition:
        any of them
}