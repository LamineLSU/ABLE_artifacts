rule KeyPatternsDetection
{
    meta:
        description = "Detects key patterns from code analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-15"

    strings:
        $pattern0 = { E8 DA FD FF FF 83 C4 20 }  // Call to 0041215Fh followed by add esp, 20
        $pattern1 = { FF 15 B0 62 45 00 }        // Call to Sleep function
        $pattern2 = { 68 44 41 46 00 E8 AC 9E FF FF }  // Push "FAKE" followed by call to 00408098h

    condition:
        all of them
}