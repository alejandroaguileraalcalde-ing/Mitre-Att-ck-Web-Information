# Mitre Att&ck Web Information
Get Mitre Att&ck Information from its webpage into list, csv or xml files in Spanish.

# How it works: 

## Individual search with a .txt file with multiple Mitigations, Groups, Detections, etc. that you want to be looked up.

Requirements: 


    Txt file with a list of Mitigations/Detection/Groups/Software that you want to search. 

Usage: 


<b>Mitigation_info_txtFile('Mitigations_list_Filename')</b>

<b>Detection_info_txtFile('Detection_list_Filename')</b>

<b>Group_info_txtFile('Group_list_Filename')</b>

<b>Software_info_txtFile('Software_list_Filename')</b>

This will generate a .csv file for earch search. 

## Global information about techniques: Tactics, Mitigations, Detections, Groups, Software, etc.

Write into a .txt file (ex: Techniques_list_Filename.txt) a list of techniques and subtechniques that you want to be looked up.

Requirements: 


    Txt file with a list of Techniques/SubTechniques that you want to search. 

Usage: 


<b>Tecnicas_info_txtFile('Techniques_list_Filename')</b>

This will generate some .xml files with the information. 

## individual search

Requirements: 


    None 

Usage: 


<b>Group_info('G0032')</b>

<b>Software_info('S0691')</b>

<b>Detection_info('DS0017')</b>

<b>Mitigation_info('M1029')</b>

### Example:


### Group_info('G0032') ###
['G0032', 'Lazarus Group', 'NaN', 'NaN', 'Lazarus Group es un grupo de amenazas cibernéticas patrocinado por el estado de Corea del Norte que ha sido atribuido a la Oficina General de Reconocimiento.[1][2] El grupo ha estado activo desde al menos 2009 y, según los informes, fue responsable del destructivo ataque con limpiaparabrisas de noviembre de 2014 contra Sony Pictures Entertainment como parte de una campaña denominada Operación Blockbuster de Novetta. El malware utilizado por Lazarus Group se correlaciona con otras campañas informadas, incluidas Operation Flame, Operation 1Mission, Operation Troy, DarkSeoul y Ten Days of Rain. [3]', '31 May 2017', '23 August 2022', ': Labyrinth Chollima, HIDDEN COBRA, Guardians of Peace, ZINC, NICKEL ACADEMY']

### Software_info('S0691') ###
['S0691', 'Neoichor', 'MALWARE', 'Windows', 'Neoichor es un malware C2 utilizado por Ke3chang desde al menos 2019; familias de malware similares utilizadas por el grupo incluyen Leeson y Numbldea.[1]', '22 March 2022', '11 April 2022', 'NaN']

### Detection_info('DS0017') ###
['DS0017', 'Command', 'Container, Host', 'Containers, Linux, Network, Windows, macOS', 'Una directiva dada a un programa de computadora, que actúa como un intérprete de algún tipo, para realizar una tarea específica[1][2]', 'Una directiva dada a un programa de computadora, que actúa como un intérprete de algún tipo, para realizar una tarea específica[1][2]', [['Command Execution', 'La ejecución de una línea de texto, potencialmente con argumentos, creada a partir del código del programa (por ejemplo, un cmdlet ejecutado a través de powershell.exe, comandos interactivos como &gt;dir, ejecuciones de shell, etc.)'], ['Command Execution', 'La ejecución de una línea de texto, potencialmente con argumentos, creada a partir del código del programa (por ejemplo, un cmdlet ejecutado a través de powershell.exe, comandos interactivos como &gt;dir, ejecuciones de shell, etc.)']], '20 October 2021', '21 October 2022']

### Mitigation_info('M1029') ###  
['M1029', 'Remote Data Storage', 'T1119', 'T1565/001, T1070/001', 'Utilice el registro de seguridad remoto y el almacenamiento de archivos confidenciales donde el acceso se puede controlar mejor para evitar la exposición de los datos del registro de detección de intrusos o la información confidencial.', '06 June 2019', '06 June 2019']

