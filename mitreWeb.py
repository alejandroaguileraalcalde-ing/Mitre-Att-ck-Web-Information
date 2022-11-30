import json
import os
import subprocess
import requests
import nvdlib
import time
import sys
import pandas as pd
import re
from deep_translator import GoogleTranslator
import csv
import subprocess


CLEANR = re.compile('<.*?>') 
technique = ''


def traducir(texto):
    translated = GoogleTranslator(source='auto', target='es').translate(texto)
    return translated


def cleanhtml(raw_html):
  cleantext = re.sub(CLEANR, '', raw_html)
  return cleantext


def CsvToExcel(nombre_fichero):
   datos = pd.read_csv(nombre_fichero+'.csv').rename(columns=lambda x: str(x))

   with pd.ExcelWriter(nombre_fichero+'.xlsx', engine='xlsxwriter') as excelfile:
    workbook = excelfile.book
    # Agregamos datos al libro
    sheetname = nombre_fichero
    datos.to_excel(excelfile, sheet_name=sheetname, index=False) 

def borrar_fichero(fichero):
    bashCommand = "rm "+fichero
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()  





def proceso(technique, esSubtechnique, Technique_number, subTechnique_number):
    #technique = 'T1486'
    URL = 'https://attack.mitre.org/techniques/'+str(technique) +'/'
    page = requests.get(URL , verify=False).text
    texto = page
    """
    print(page)

    f = open("test.txt", "w")
    f.write(page)
    f.close()


    f = open("test.txt", "r")
    texto = f.read()
    f.close()
    """

    lista_grupo_id = list() 
    lista_grupo_nombre = list() 
    lista_mitigations_id = list() 
    lista_mitigations_nombre = list() 
    lista_detection_id = list() 
    lista_detection_nombre = list()
    lista_grupo_description = list()
    lista__description = list()
    lista_grupo_asociado = list()
    lista_detection_data_source = list()
    lista_detection_description_data_component = list()
    lista_detection_data_source_description = list()
    lista_detection_data_source_plataforma = list()

    ########################
    #info tecnica y tactica: 
    ########################
    nombre_tecnica = ''
    nombre_tactica_asociada = ''
    nombre_tactica_asociada_completo = ''
    id_tactica = ''
    descripcion_tactica_asociada = ''

    try: 
        nombre_tecnica = texto.split('<h1 id=\"\">')[1].split('</h1>')[0].strip()
        
        id_tactica = page.split('Tactic:</span>')[1].split('/tactics/')[1].split('\">')[0].strip()
        nombre_tactica_asociada = page.split('Tactic:</span>')[1].split('\">')[1].split('</a>')[0].strip()
        nombre_tactica_asociada_completo = id_tactica +' - '+nombre_tactica_asociada
        
        time.sleep(1)
        URL = 'https://attack.mitre.org/tactics/'+str(id_tactica) +'/'
        page1 = requests.get(URL , verify=False).text
        descripcion_tactica_asociada = page1.split('<div class="description-body">')[1].split('<p>')[1].split('</p>')[0]
        try:
            descripcion_tactica_asociada = traducir(descripcion_tactica_asociada)
        except:
            pass
    except: 

        pass


    ###########
    #grupos: 
    ###########
    try:

        inicio_busqueda = """
                          <h2 class="pt-3" id ="examples">Procedure Examples</h2>
                            <table class="table table-bordered table-alternate mt-2">
                                <thead>
                                    <tr>
                                        <th scope="col">ID</th>
                                        <th scope="col">Name</th>
                                        <th scope="col">Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                          """
        #fin_busqueda = '</a>' 
        inicio_busqueda2 = '<tr>'
        inicio_busqueda = inicio_busqueda.strip()
        t = texto.split(inicio_busqueda)
        """
        try:
            f = open("test2.txt", "w")
            f.write(t[1])
            f.close()
            print('test2')
        except:
            f = open("test3.txt", "w")
            f.write(t[0])
            f.close()
            print('test3')
            pass
        """
        

        t2 = t[1].split(inicio_busqueda2)
        for i in t2:
            try: 
                aux_text = i.split('<td>')[1].split('</td>')
                aux_text2 = i.split('<td>')[2].split('</td>')
                aux_text3 = i.split('<td>')[3].split('</td>') #descripcion
                identificador = aux_text[0].split('\">')[1].split('</a>')[0].strip()
                lista_grupo_id.append(identificador)
                
                

                nombre_grupo = aux_text2[0].split('\">')[1].split('</a>')[0].strip()
                lista_grupo_nombre.append(nombre_grupo)

                description_grupo = aux_text3[0].split('<p>')[1].split('</p>')[0].strip()
                description_grupo = cleanhtml(description_grupo).strip()
                description_grupo = traducir(description_grupo)
                #print('description es ')
                #print(description_grupo)
                #print('para el ID '+str(identificador))
                lista_grupo_description.append(description_grupo)
            except:
                pass   
    except: 
        pass 


    ###########
    #Mitigations: 
    ###########
    try:

        inicio_busqueda = """
                          <h2 class="pt-3" id ="mitigations">Mitigations</h2>
                                <table class="table table-bordered table-alternate mt-2">
                                    <thead>
                                        <tr> 
                                            <th scope="col">ID</th>
                                            <th scope="col">Mitigation</th>
                                            <th scope="col">Description</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                          """
        #fin_busqueda = '</a>' 
        inicio_busqueda2 = '<tr>'
        inicio_busqueda = inicio_busqueda.strip()
        t = texto.split(inicio_busqueda)
        f = open("test2.txt", "w")
        f.write(t[1])
        f.close()
        t2 = t[1].split(inicio_busqueda2)
        for i in t2:
            try:
                aux_text = i.split('<td>')[1].split('</td>')
                #print(aux_text)
                aux_text2 = i.split('<td>')[2].split('</td>')
                identificador = aux_text[0].split('\">')[1].split('</a>')[0].strip()
                lista_mitigations_id.append(identificador)

                nombre_grupo = aux_text2[0].split('\">')[1].split('</a>')[0].strip()
                lista_mitigations_nombre.append(nombre_grupo)
            except:
                pass    
    except: 
        pass   


    ###########
    #Detections: 
    ###########

    try:
        inicio_busqueda = 'Detects</th>'
        #fin_busqueda = '</a>' 
        inicio_busqueda2 = '<tr class=\"datasource\"'
        t = texto.split(inicio_busqueda)
        t2 = t[1].split(inicio_busqueda2)
        """
        f = open("test3.txt", "w")
        f.write(t[1])
        f.close()
        f = open("test2.txt", "w")
        f.write(str(t2))
        f.close()
        """
        for i in t2:
            try: 
                aux_text = i.split('<td>')[1].split('</td>')
                aux_text2 = i.split('<td>')[2].split('</td>')
                
                identificador = aux_text[0].split('\">')[1].split('</a>')[0].strip()
                lista_detection_id.append(identificador)

                nombre_grupo = aux_text2[0].split('\">')[1].split('</a>')[0].strip()
                lista_detection_nombre.append(nombre_grupo)

                try:
                    aux_text3 = i.split('<td>')[3].split('</td>')
                    aux_i = aux_text3[0].split('<p>')[1].split('</p>')[0].strip()
                    aux_i = cleanhtml(aux_i)
                    lista_detection_description_data_component.append(aux_i)
                except: 
                    pass
                try:
                    aux_text4 = i.split('<td class="nowrap">')[1].split('</td>')
                    lista_detection_data_source.append(aux_text4[0].split('\">')[1].split('</a>')[0].strip())

                    ####################3
                    time.sleep(1)
                    URL = 'https://attack.mitre.org/datasources/'+str(identificador) +'/'
                    page1 = requests.get(URL , verify=False).text
                    descripcion_data_source = page1.split('<div class="description-body">')[1].split('<p>')[1].split('</p>')[0]
                    descripcion_data_source = cleanhtml(descripcion_data_source)
                    try:
                        descripcion_data_source = traducir(descripcion_data_source)
                        lista_detection_data_source_description.append(descripcion_data_source)
                    except:
                        lista_detection_data_source_description.append('')
                        pass

                    try:
                        plataforma = page1.split('Platforms:&nbsp;</span>')[1].split('</div>')[0].strip()
                        lista_detection_data_source_plataforma.append(plataforma)
                    except:
                        lista_detection_data_source_plataforma.append('')
                        pass
                    ######################

                except: 
                    pass

                    
            except:
                pass    
    except: 
        pass   


    ###########
    #Description
    ###########  
    try:
        t = texto.split('<div class="description-body">')[1].split('<p>')[1].split('</p>')[0]
        description = cleanhtml(t) 
        description = traducir(description) #
        lista__description.append(description)
        plataforma = page.split('Platforms:&nbsp;</span>')[1].split('</div>')[0].strip()
        
    except: 
        lista__description.append('NaN')
        plataforma = 'NaN'
        pass  


    """
    #sobra 3 ultimos. 
    print(lista_grupo_id)
    print(lista_grupo_nombre)
    #bien 
    print(lista_detection_id)
    #sobra el ultimo
    print(lista_mitigations_id)
    print(lista_mitigations_nombre)
    """

    #solucion de errores: 
    lista_grupo_id = lista_grupo_id[:(len(lista_grupo_id)-3)]
    lista_grupo_nombre = lista_grupo_nombre[:(len(lista_grupo_nombre)-3)]

    lista_mitigations_id = lista_mitigations_id[:(len(lista_mitigations_id)-1)]
    lista_mitigations_nombre = lista_mitigations_nombre[:(len(lista_mitigations_nombre)-1)]
    ####


    #para excel: 
    #GRUPOS
    texto_lista_grupo_id = ''
    a = 0
    for i in lista_grupo_id:
        if a !=0:
            texto_lista_grupo_id = texto_lista_grupo_id + ', '+i
        else: 
            texto_lista_grupo_id = i
            a = a +1

    #MITIGACION
    texto_lista_mitigacion_id = ''
    a = 0
    for i in lista_mitigations_id:
        if a !=0:
            texto_lista_mitigacion_id = texto_lista_mitigacion_id + ', '+i
        else: 
            texto_lista_mitigacion_id = i
            a = a +1

    #DETECCION
    texto_lista_deteccion_id = ''
    a = 0
    for i in lista_detection_id:
        if a !=0:
            texto_lista_deteccion_id = texto_lista_deteccion_id + ', '+i
        else: 
            texto_lista_deteccion_id = i
            a = a +1
    #hay que hacer lo mismo para deteccion y mitigacion....******
    #print(texto_lista_grupo_id)



    #df_sheet_name = pd.read_excel(f'sample-{i}.xlsx', sheet_name='sheet2')
    nombre_documento_excel = 'Base_file.xlsx'
    nombre_hoja = 'Procedimientos'
    df_sheet_name = pd.read_excel(nombre_documento_excel, sheet_name=nombre_hoja)
    lista_grupos_usados = df_sheet_name['IDENTIFICADOR'].tolist()
    lista_NOMBRE = df_sheet_name['NOMBRE'].tolist()
    lista_DESCRIPTION = df_sheet_name['DESCRIPCIÓN'].tolist()
    #print(lista_grupos_usados)

    #mitigaciones:
    #df_sheet_name = pd.read_excel(f'sample-{i}.xlsx', sheet_name='sheet2')
    nombre_documento_excel = 'Base_file.xlsx'
    nombre_hoja = 'Mitigación'
    df_sheet_name_2 = pd.read_excel(nombre_documento_excel, sheet_name=nombre_hoja)
    lista_grupos_usados_mitigacion = df_sheet_name_2['IDENTIFICADOR'].tolist()
    lista_NOMBRE_mitigacion = df_sheet_name_2['MITIGACIÓN'].tolist()
    lista_DESCRIPTION_mitigacion = df_sheet_name_2['DESCRIPCIÓN'].tolist()
    #
    lista_mitigaciones_nuevos = list()
    lista_mitigaciones_nuevos_nombre = list()
    lista_mitigaciones_nuevos_description = list()
    u = 0
    for i in lista_mitigations_id: 
        if str(i) in lista_grupos_usados_mitigacion:
            pass
        else:
            #print(i)
            lista_mitigaciones_nuevos.append(i)
            lista_mitigaciones_nuevos_nombre.append(lista_mitigations_nombre[u])
            #lista_mitigaciones_nuevos_description.append(lista_mitigations[u])
        u = u +1


    #print('lista de grupos que hay que anadir al excel...')


    #detecciones
    #df_sheet_name = pd.read_excel(f'sample-{i}.xlsx', sheet_name='sheet2')
    nombre_documento_excel = 'Base_file.xlsx'
    nombre_hoja = 'Detección'
    df_sheet_name_2 = pd.read_excel(nombre_documento_excel, sheet_name=nombre_hoja)
    lista_detecciones_usadas = df_sheet_name_2['IDENTIFICADOR'].tolist()
    #
    lista_detecciones_nuevos = list()
    lista_detecciones_nuevos_nombre = list()
    lista_detecciones_nuevos_description = list()
    #
    lista_detection_nuevos_data_source = list()
    lista_detection_nuevos_description_data_component = list()
    lista_detection_nuevos_data_source_description = list()
    lista_detection_nuevos_data_source_plataforma = list()
    u = 0
    for i in lista_detection_id: 
        if str(i) in lista_detecciones_usadas:
            pass
        else:
            #print(i)
            lista_detecciones_nuevos.append(i)
            lista_detecciones_nuevos_nombre.append(lista_detection_nombre[u])
            #
            lista_detection_nuevos_data_source.append(lista_detection_data_source[u])
            lista_detection_nuevos_description_data_component.append(lista_detection_description_data_component[u])
            lista_detection_nuevos_data_source_description.append(lista_detection_data_source_description[u])
            lista_detection_nuevos_data_source_plataforma.append(lista_detection_data_source_plataforma[u])
            #lista_mitigaciones_nuevos_description.append(lista_mitigations[u])
        u = u +1


    #print('lista de grupos que hay que anadir al excel...')

    ###

    lista_grupos_nuevos = list()
    lista_grupos_nuevos_nombre = list()
    lista_grupos_nuevos_description = list()
    u = 0
    for i in lista_grupo_id: 
        if str(i) in lista_grupos_usados:
            pass
        else:
            #print(i)
            lista_grupos_nuevos.append(i)
            lista_grupos_nuevos_nombre.append(lista_grupo_nombre[u])
            lista_grupos_nuevos_description.append(lista_grupo_description[u])
        u = u +1

    


    ###################
    #descripcion y mas info de cada grupo: 
    #lista_grupos_nuevos_description = list()
    lista_grupos_nuevos_tipos = list()
    lista_grupos_nuevos_plataforma = list()
    for i in lista_grupos_nuevos:
        try:
            time.sleep(1)
            URL = 'https://attack.mitre.org/software/'+str(i) +'/'
            page = requests.get(URL , verify=False).text

            t = page.split('<div class="description-body">')[1].split('<p>')[1].split('</p>')[0]
            tipo = page.split('Type</span>:')[1].split('</div>')[0].strip()
            plataforma = page.split('Platforms</span>:')[1].split('</div>')[0].strip()
            description = cleanhtml(t) 
            description = traducir(description) #
            lista_grupos_nuevos_description.append(description)
            lista_grupos_nuevos_tipos.append(tipo)
            lista_grupos_nuevos_plataforma.append(plataforma)
            
        except: 
            try:
                
                time.sleep(1)
                URL = 'https://attack.mitre.org/groups/'+str(i) +'/'
                page = requests.get(URL , verify=False).text
                t = page.split('<div class="description-body">')[1].split('<p>')[1].split('</p>')[0]
                tipo = page.split('Type</span>:')[1].split('</div>')[0].strip()
                plataforma = page.split('Platforms</span>:')[1].split('</div>')[0].strip()
                description = cleanhtml(t) 
                description = traducir(description) #
                lista_grupos_nuevos_description.append(description)
                lista_grupos_nuevos_tipos.append(tipo)
                lista_grupos_nuevos_plataforma.append(plataforma)
                
            except: 
                lista_grupos_nuevos_description.append('NaN')
                lista_grupos_nuevos_tipos.append('NaN')
                lista_grupos_nuevos_plataforma.append('NaN')


    ###################
    #descripcion y mas info de cada mitigacion: 
    lista_mitigacion_nuevos_description = list()
    lista_mitigacion_nuevos_tecnicas_mitigadas = list()
    for i in lista_mitigaciones_nuevos:
        try:
            time.sleep(1)
            URL = 'https://attack.mitre.org/mitigations/'+str(i) +'/'
            page = requests.get(URL , verify=False).text
            t = page.split('<div class="description-body">')[1].split('<p>')[1].split('</p>')[0]
            tec_aux = page.split('<tr class="technique ics" id="ics">')
            #
            texto_aux = ''
            uu = 0
            
            for a in tec_aux:
                
                
                try:
                    #techniques_mitigadas = a.split('</tr>')[0].split('<a href=\"/techniques/')[1].split('\">')[0]
                    techniques_mitigadas = a.split('</tr>')[1].split('<a href=\"/techniques/')[1].split('\">')[0]
                    if uu !=0:
                        texto_aux = texto_aux + ', '+techniques_mitigadas
                    else: 
                        texto_aux = techniques_mitigadas
                        uu = uu +1
                except:
                    pass  
                """
                print('texto_aux')
                print(texto_aux) 
                """
            lista_mitigacion_nuevos_tecnicas_mitigadas.append(texto_aux) 
            #lista_mitigation_nuevos_tecnicas_mitigadas.append(techniques_mitigadas)
            description = cleanhtml(t) 
            description = traducir(description) #
            lista_mitigacion_nuevos_description.append(description)

        except: 
            try:
                time.sleep(1)
                URL = 'https://attack.mitre.org/mitigations/'+str(i) +'/'
                page = requests.get(URL , verify=False).text
                t = page.split('<div class="description-body">')[1].split('<p>')[1].split('</p>')[0]
                #
                texto_aux = ''
                uu = 0
                for a in tec_aux:
                    try:
                        #techniques_mitigadas = a.split('</tr>')[0].split('<a href=\"/techniques/')[1].split('\">')[0]
                        techniques_mitigadas = a.split('</tr>')[1].split('<a href=\"/techniques/')[1].split('\">')[0]
                        if uu !=0:
                            texto_aux = texto_aux + ', '+techniques_mitigadas
                        else: 
                            texto_aux = techniques_mitigadas
                            uu = uu +1
                    except:
                        pass   
                lista_mitigacion_nuevos_tecnicas_mitigadas.append(texto_aux) 
                description = cleanhtml(t) 
                description = traducir(description) #
                lista_mitigacion_nuevos_description.append(description)
            except: 
                lista_mitigacion_nuevos_description.append('NaN')
    

    
    ## datos comunes:
    aux_name = technique +' - '+ nombre_tecnica
    #mejorar para entender si es tecnica o subtecnica si el technique tiene / o no....
    if esSubtechnique == 1:
        #header1 = ['TACTICA', 'DESCRIPCIÓN TÁCTICA', 'TÉCNICA', 'DESCRIPCIÓN TÉCNICA', 'SUB-TÉCNICA', 'DESCRIPCIÓN SUB-TÉCNICA', 'PLATAFORMA', 'PROCEDIMIENTOS RELACIONADOS', 'MITIGACIONES RELACIONADAS', 'DETECCIONES RELACIONADAS', 'DEFENSAS QUE SUPERA', 'PERMISOS REQUERIDOS', 'SE PUEDE USAR EN REMOTO']
        aux_name = Technique_number+'/'+subTechnique_number +' - '+ nombre_tecnica.split(':</span>')[1].strip()
        
        
        ###########
        #Description
        ###########  
        description_aux = ''
        try: 

            URL = 'https://attack.mitre.org/techniques/'+str(Technique_number) +'/'
            page = requests.get(URL , verify=False).text
            texto = page

            t = texto.split('<div class="description-body">')[1].split('<p>')[1].split('</p>')[0]
            description = ''
            description_aux = cleanhtml(t) 
            description_aux = traducir(description_aux) #
            
        except: 
            description_aux = 'NaN'
        ###
        fila = [nombre_tactica_asociada_completo, descripcion_tactica_asociada,  technique.split('/')[0].strip(), description_aux, aux_name, lista__description[0], plataforma, texto_lista_grupo_id, texto_lista_mitigacion_id, texto_lista_deteccion_id, '', '', '']
        with open('Tacticas_y_tecnicas.csv', 'a', encoding='UTF8') as f:
            writer = csv.writer(f)
            writer.writerow(fila)
    else:
        fila = [nombre_tactica_asociada_completo, descripcion_tactica_asociada, aux_name, lista__description[0], '', '', plataforma, texto_lista_grupo_id, texto_lista_mitigacion_id, texto_lista_deteccion_id, '', '', '']
        with open('Tacticas_y_tecnicas.csv', 'a', encoding='UTF8') as f:
            writer = csv.writer(f)
            writer.writerow(fila)
                
    CsvToExcel('Tacticas_y_tecnicas')
    
    

    y = 0
    for i in lista_grupos_nuevos: 
        fila2 = [i, lista_grupos_nuevos_nombre[y], lista_grupos_nuevos_description[y], '', lista_grupos_nuevos_tipos[y], lista_grupos_nuevos_plataforma[y], '']
        with open('Procedimientos.csv', 'a', encoding='UTF8') as f:
            writer = csv.writer(f)
            writer.writerow(fila2)
        y = y +1
   
    CsvToExcel('Procedimientos')

    
    y = 0
    for i in lista_mitigaciones_nuevos_nombre: 
        a = traducir(i)
        fila3 = [lista_mitigaciones_nuevos[y], a, lista_mitigacion_nuevos_description[y], '', lista_mitigacion_nuevos_tecnicas_mitigadas[y]]
        with open('Mitigacion.csv', 'a', encoding='UTF8') as f:
            writer = csv.writer(f)
            writer.writerow(fila3)
        y = y +1


    CsvToExcel('Mitigacion')

    
    y = 0
    for i in lista_detecciones_nuevos_nombre: 
        a = traducir(i)
        tt = cleanhtml(lista_detection_nuevos_description_data_component[y])
        tt = traducir(tt)
        fila4 = [lista_detecciones_nuevos[y], a, tt, lista_detection_nuevos_data_source[y], lista_detection_nuevos_data_source_description[y], '', '', lista_detection_nuevos_data_source_plataforma[y]]
        with open('Deteccion.csv', 'a', encoding='UTF8') as f:
            writer = csv.writer(f)
            writer.writerow(fila4)
        y = y +1
    CsvToExcel('Deteccion')




def Mitigation_info(MitigationID):

    
    

        
        nombre = ''
        tecnicas_mitigadas_ics = '' 
        tecnicas_mitigadas_enterprise = ''  
        description = ''
        Created = ''
        Last_Modified = ''
        tec_aux =  ''
        tec_aux_enterprise =  ''

        ##################3
        time.sleep(1)
        URL = 'https://attack.mitre.org/mitigations/'+str(MitigationID) +'/'
        page = requests.get(URL , verify=False).text
        t = page.split('<div class="description-body">')[1].split('<p>')[1].split('</p>')[0]
        try:
            tec_aux = page.split('<tr class="technique ics" id="ics">')
            tec_aux = tec_aux[1:]
        except:
            pass   
        try:
            tec_aux_enterprise = page.split('<tr class=\"technique enterprise\" id=\"enterprise\">')
            tec_aux_enterprise = tec_aux_enterprise[1:]
        except:
            pass
        #

        texto_aux = ''
        texto_aux_enterprise = ''
        uu = -1
        #techniques ics
        for a in tec_aux:
            
            try:
                #techniques_mitigadas = a.split('</tr>')[0].split('<a href=\"/techniques/')[1].split('\">')[0]
                tecnicas_mitigadas_ics = a.split('<a href=\"/techniques/')[1].split('\">')[0]
                #print('tecnicas_mitigadas_ics')
                #print(tecnicas_mitigadas_ics)
                if uu >= 0:
                    texto_aux = texto_aux + ', '+tecnicas_mitigadas_ics
                else: 
                    texto_aux = tecnicas_mitigadas_ics
                    uu = uu +1
            except:
                pass  
        
        ##
        #techniques enterprise
        uu = -1
        for a in tec_aux_enterprise:
            
            try:
                #techniques_mitigadas = a.split('</tr>')[0].split('<a href=\"/techniques/')[1].split('\">')[0]
                tecnicas_mitigadas_enterprise = a.split('<a href=\"/techniques/')[1].split('\">')[0]
                #print('tecnicas_mitigadas')
                #print(tecnicas_mitigadas_enterprise)
                if uu >= 0:
                    texto_aux_enterprise = texto_aux_enterprise + ', '+tecnicas_mitigadas_enterprise
                else: 
                    texto_aux_enterprise = tecnicas_mitigadas_enterprise
                    uu = uu +1
            except:
                pass  
        tecnicas_mitigadas_enterprise = texto_aux_enterprise
        tecnicas_mitigadas_ics = texto_aux
        #
        description = cleanhtml(t) 
        description = traducir(description) #
        
        
        #################3

        aux = """
              <div class="container-fluid">
                    <h1>
              """
        aux = aux.strip()
        nombre = page.split(aux)[1].split('</h1>')[0].strip()

        t = page.split('<div class="description-body">')[1].split('<p>')[1].split('</p>')[0]
        try:
            Created = page.split('Created:&nbsp;</span>')[1].split('</div>')[0].strip()
        except: 
            Created = 'NaN'
        try:
            Last_Modified = page.split('Last Modified:&nbsp;</span>')[1].split('</div>')[0].strip()
        except: 
            Last_Modified = 'NaN'
        
        lista_response = [MitigationID, nombre, tecnicas_mitigadas_ics, tecnicas_mitigadas_enterprise, description, Created,  Last_Modified]

        #print(lista_response)
        return lista_response 


def Detection_info(DetectionID):

    
        nombre = ''
        Collection_Layers = ''
        plataforma = ''   
        description = ''
        Created = ''
        Last_Modified = ''
        descripcion_data_source = ''

        ####################3
        time.sleep(1)
        URL = 'https://attack.mitre.org/datasources/'+str(DetectionID) +'/'
        page = requests.get(URL , verify=False).text
        
        descripcion_data_source = page.split('<div class="description-body">')[1].split('<p>')[1].split('</p>')[0]
        descripcion_data_source = cleanhtml(descripcion_data_source)
        try:
            descripcion_data_source = traducir(descripcion_data_source)
        except:
            pass

        try:
            plataforma = page.split('Platforms:&nbsp;</span>')[1].split('</div>')[0].strip()
        except:
            pass
        
        aux = """
              <div class="container-fluid">
                    <h1>
              """
        aux = aux.strip()
        nombre = page.split(aux)[1].split('</h1>')[0].strip()

        t = page.split('<div class="description-body">')[1].split('<p>')[1].split('</p>')[0]
        try:
            
            Collection_Layers = page.split('Collection Layers:&nbsp;</span>')[1].split('</div>')[0].strip()
        except: 
            Collection_Layers = 'NaN'
        try:
            description = cleanhtml(t) 
            description = traducir(description) #
        except: 
            description = 'NaN'
        try:
            Created = page.split('Created:&nbsp;</span>')[1].split('</div>')[0].strip()
        except: 
            Created = 'NaN'
        try:
            Last_Modified = page.split('Last Modified:&nbsp;</span>')[1].split('</div>')[0].strip()
        except: 
            Last_Modified = 'NaN'


        #anadir data componets y su description, pueden ser varios..lista
        try:
            Data_components_list = page.split('<h4 class="pt-3">'+nombre.strip()+':')
            Data_components_list_info = list()
            aux_int = 0
            for i in Data_components_list:
                if (aux_int != 0):
                    Data_components_nombre = i.split('</h4>')[0].strip()
                    
                    Data_components_description = i.split('<p>')[1].split('</p>')[0].strip()
                    Data_components_description= cleanhtml(Data_components_description) 
                    Data_components_description = traducir(Data_components_description)

                    Data_components_list_info.append([Data_components_nombre, Data_components_description])
                else: 
                    aux_int = 1
        except: 
            Data_components_list_info = 'NaN'
        
        lista_response = [DetectionID, nombre, Collection_Layers, plataforma, description, descripcion_data_source, Data_components_list_info,Created,  Last_Modified]

        #print(lista_response)
        return lista_response  

def Group_info(ProcedureID):

    
    

        
        nombre = ''
        tipo = ''
        plataforma = ''   
        description = ''
        Created = ''
        Last_Modified = ''
        Associated_Groups = ''

        time.sleep(1)
        URL = 'https://attack.mitre.org/groups/'+str(ProcedureID) +'/'
        page = requests.get(URL , verify=False).text

        aux = """
              <div class="container-fluid">
                    <h1>
              """
        aux = aux.strip()
        nombre = page.split(aux)[1].split('</h1>')[0].strip()

        t = page.split('<div class="description-body">')[1].split('<p>')[1].split('</p>')[0]
        try:
            tipo = page.split('Type</span>:')[1].split('</div>')[0].strip()
        except: 
            tipo = 'NaN'
        try:
            plataforma = page.split('Platforms</span>:')[1].split('</div>')[0].strip()
        except: 
            plataforma = 'NaN'
        try:
            description = cleanhtml(t) 
            description = traducir(description) #
        except: 
            description = 'NaN'
        try:
            Created = page.split('Created:&nbsp;</span>')[1].split('</div>')[0].strip()
        except: 
            Created = 'NaN'
        try:
            Last_Modified = page.split('Last Modified:&nbsp;</span>')[1].split('</div>')[0].strip()
        except: 
            Last_Modified = 'NaN'
        try:
            Associated_Groups = page.split('Associated Groups</span>')[1].split('</div>')[0].strip()
        except: 
            Associated_Groups = 'NaN'
        
        lista_response = [ProcedureID, nombre, tipo, plataforma, description, Created,  Last_Modified, Associated_Groups]

        #print(lista_response)
        return lista_response  

def Software_info(SoftwareID):

    
    

        
        nombre = ''
        tipo = ''
        plataforma = ''   
        description = ''
        Created = ''
        Last_Modified = ''
        Associated_Groups = ''

        time.sleep(1)
        URL = 'https://attack.mitre.org/software/'+str(SoftwareID) +'/'
        page = requests.get(URL , verify=False).text

        aux = """
              <div class="container-fluid">
                    <h1>
              """
        aux = aux.strip()
        nombre = page.split(aux)[1].split('</h1>')[0].strip()

        t = page.split('<div class="description-body">')[1].split('<p>')[1].split('</p>')[0]
        try:
            tipo = page.split('Type</span>:')[1].split('</div>')[0].strip()
        except: 
            tipo = 'NaN'
        try:
            plataforma = page.split('Platforms</span>:')[1].split('</div>')[0].strip()
        except: 
            plataforma = 'NaN'
        try:
            description = cleanhtml(t) 
            description = traducir(description) #
        except: 
            description = 'NaN'
        try:
            Created = page.split('Created:&nbsp;</span>')[1].split('</div>')[0].strip()
        except: 
            Created = 'NaN'
        try:
            Last_Modified = page.split('Last Modified:&nbsp;</span>')[1].split('</div>')[0].strip()
        except: 
            Last_Modified = 'NaN'
        try:
            Associated_Groups = page.split('Associated Groups</span>')[1].split('</div>')[0].strip()
        except: 
            Associated_Groups = 'NaN'
        
        lista_response = [SoftwareID, nombre, tipo, plataforma, description, Created,  Last_Modified, Associated_Groups]

        #print(lista_response)
        return lista_response 





def Group_info_txtFile(Fichero):

    
    file1 = open(Fichero+'.txt', 'r')
    lista = file1.readlines()

    header = ['IDENTIFICADOR', 'NOMBRE', 'TIPO', 'PLATAFORMA', 'DESCRIPCION', 'CREATED', 'LAST MODIFIED', 'ASSOCIATED GROUPS']
    with open('Grupos.csv', 'w', encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(header)

    print('Analizando los Grupos uno a uno:\n')
    for i in lista:
        print('Grupo: '+i)
        fila = Group_info(i.strip())

        with open('Grupos.csv', 'a', encoding='UTF8') as f:
            writer = csv.writer(f)
            writer.writerow(fila)

def Software_info_txtFile(Fichero):

    file1 = open(Fichero+'.txt', 'r')
    lista = file1.readlines()

    header = ['IDENTIFICADOR', 'NOMBRE', 'TIPO', 'PLATAFORMA', 'DESCRIPCION', 'CREATED', 'LAST MODIFIED', 'ASSOCIATED GROUPS']
    with open('Software.csv', 'w', encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(header)

    print('Analizando los Softwares uno a uno:\n')
    for i in lista:
        print('Software: '+i)
        fila = Software_info(i.strip())

        with open('Software.csv', 'a', encoding='UTF8') as f:
            writer = csv.writer(f)
            writer.writerow(fila)

def Detection_info_txtFile(Fichero):


    file1 = open(Fichero+'.txt', 'r')
    lista = file1.readlines()

    header = ['IDENTIFICADOR', 'DATA SOURCE', 'COLLECTION LAYERS', 'PLATAFORMA', 'DESCRIPCION', 'DESCRIPCION DATA SOURCE', 'DATA COMPONENTS AND DATA COMPONENTS DESCRIPTION','LAST MODIFIED']
    with open('Deteccion.csv', 'w', encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(header)


    print('Analizando las Detecciones una a una:\n')
    for i in lista:
        print('Detection: '+i)
        fila = Detection_info(i.strip())

        with open('Deteccion.csv', 'a', encoding='UTF8') as f:
            writer = csv.writer(f)
            writer.writerow(fila)

def Mitigation_info_txtFile(Fichero):


    file1 = open(Fichero+'.txt', 'r')
    lista = file1.readlines()

    header = ['IDENTIFICADOR', 'NOMBRE', 'TECNICAS MITIGADAS ICS', 'TECNICAS MITIGADAS ENTERPRISE', 'DESCRIPCION', 'CREATED', 'LAST MODIFIED']
    with open('Mitigacion.csv', 'w', encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(header)

    print('Analizando las Mitigaciones una a una:\n')
    for i in lista:
        print('Mitigation: '+i)
        fila = Mitigation_info(i.strip())

        with open('Mitigacion.csv', 'a', encoding='UTF8') as f:
            writer = csv.writer(f)
            writer.writerow(fila)


def Tecnicas_info_txtFile(Fichero):


    ##creacion de csv para guardar resultados (solo primera vez, luego quitar):
    header1 = ['TACTICA', 'DESCRIPCIÓN TÁCTICA', 'TÉCNICA', 'DESCRIPCIÓN TÉCNICA', 'SUB-TÉCNICA', 'DESCRIPCIÓN SUB-TÉCNICA', 'PLATAFORMA', 'PROCEDIMIENTOS RELACIONADOS', 'MITIGACIONES RELACIONADAS', 'DETECCIONES RELACIONADAS', 'DEFENSAS QUE SUPERA', 'PERMISOS REQUERIDOS', 'SE PUEDE USAR EN REMOTO']
    header2 = ['IDENTIFICADOR', 'MITIGACIÓN', 'DESCRIPCIÓN', 'CONTROLES RELACIONADOS', 'TÉCNICAS MITIGADAS']
    header3 = ['IDENTIFICADOR', 'DATA COMPONENT', 'DESCRIPCIÓN DATA COMPONENT', 'DATA SOURCE', 'DESCRIPCIÓN DATA SOURCE', 'COLLECTION LAYER', 'TECNOLOGÍA', 'PLATAFORMA']
    header4 = ['IDENTIFICADOR', 'NOMBRE', 'DESCRIPCIÓN', 'SOFTWARE ASOCIADO', 'TIPO', 'TECNOLOGÍA', 'ADICIONAL']

    with open('Tacticas_y_tecnicas.csv', 'w', encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(header1)
    with open('Mitigacion.csv', 'w', encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(header2)
    with open('Deteccion.csv', 'w', encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(header3)
    with open('Procedimientos.csv', 'w', encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(header4)


    ####

    #leer lista de tecnicas:
    file1 = open(Fichero+'.txt', 'r')
    lista_tecnicas = file1.readlines()

    print('Analizando las tecnicas una a una:\n')
    for i in lista_tecnicas:
        print('Tecnica: '+i)
        if '/' in i:
            esSubtechnique = 1
            subTechnique_number = str(i.split('/')[1].strip())
            Technique_number = str(i.split('/')[0].strip())

        else: 
            esSubtechnique = 0    
        proceso(i.strip(), esSubtechnique, Technique_number, subTechnique_number)


    print('borrando ficheros csv auxiliares...')
    borrar_fichero('Deteccion.csv')
    borrar_fichero('Mitigacion.csv')
    borrar_fichero('Procedimientos.csv')
    borrar_fichero('Tacticas_y_tecnicas.csv')


##################################

## USO INDIVIDUAL ##
#Group_info('G0032')
#Software_info('S0691')
#Detection_info('DS0017')
#Mitigation_info('M1029')

## USO CON UN FICHERO .TXT ##
#Mitigation_info_txtFile('lista_Mitigaciones')
#Detection_info_txtFile('lista_Detecciones')
#Group_info_txtFile('lista_Grupos')
#Software_info_txtFile('lista_Software')

## INFORMACION DE TODO LO RELACIONADO CON LAS TECNICAS: Tacticas, Mitigaciones, Detecciones, Grupos, Software. ##
#Tecnicas_info_txtFile('tecnicas')


##################################




