rule ExpandedPattern
{
    meta:
        description = "Expanded pattern with longer sequence for better detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    
    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 59 }  // Call to ___crtCorExitProcess followed by pop ecx
        $pattern1 = { 8B EC FF 75 08 E8 ?? ?? ?? ?? }  // mov ebp, esp; push ebp+08h; call
        $pattern2 = { FF 15 ?? ?? ?? ?? }  // call to ExitProcess

    condition:
        all of them
}