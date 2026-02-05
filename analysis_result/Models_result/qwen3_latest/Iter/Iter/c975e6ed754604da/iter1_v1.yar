rule CodePatternDetection
{
    meta:
        description = "Detects specific code patterns in memory"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $pattern0 = { 55 8B EC FF 75 08 }  // Setup: push ebp, mov ebp, push [ebp+8]
        $pattern1 = { FF 75 08 E8 ?? ?? ?? ?? }  // Push [ebp+8] followed by a call (offset unknown)
        $pattern2 = { FF 75 08 FF 15 ?? ?? ?? ?? }  // Push [ebp+8] followed by a call to ExitProcess (offset unknown)

    condition:
        all of them
}