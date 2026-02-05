rule Sample_Detection
{
    meta:
        description = "Detects a specific sample based on observed patterns"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 50 83 F8 11 74 05 }  // Pattern from 0x00401018 to 0x0040101C
        $b = { FF 15 50 60 44 00 }  // Pattern from the call to ExitProcess
        $c = { 8B 4D 1C 8B 4D 24 74 2B }  // Pattern from the mov and je sequence
    condition:
        all of them
}