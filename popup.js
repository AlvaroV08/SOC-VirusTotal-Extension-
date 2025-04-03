import { apiKey } from './apikey.js';

const messageResult = document.getElementById('result')
document.addEventListener('DOMContentLoaded', () => {
  const iocInput = document.getElementById('iocInput');
  if (iocInput) {
    iocInput.focus(); 
  }
});
//Funciones para el API de VT
function desanonimizarIoc(iocAnonimizada) {
  return iocAnonimizada.replace(/\[\.\]/g, '.');
}
function procesarIOC(ioc) {
  if (ioc.includes("[.]")) {
    return desanonimizarIoc(ioc);
  } else {
    return ioc;
  }
}

 function detectInputType(input) {
  const hashRegex = /^[a-fA-F0-9]{32,64}$/;
  const ipv4Regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([a-fA-F0-9:]+:+)+[a-fA-F0-9]+$/;
  const urlRegex = /^(?:https?:\/\/)?([\w-]+\.)+[a-z]{2,6}(:\d+)?(\/.*)?$/i;

  if (hashRegex.test(input)) {
      return "hash"
  } else if (ipv4Regex.test(input)) {
      return "IPv4"
  } else if (ipv6Regex.test(input)) {
      return "IPv6"
  } else if (urlRegex.test(input)) {
      return "URL"
  } else {
      return "Desconocido"
  }
}

document.getElementById('btnCheckIoc').addEventListener('click', async () => {
    const valueIOC = iocInput.value;
        messageResult.textContent = 'Cargando...';
    if (!valueIOC) {
      messageResult.textContent = 'Por favor, ingresa al menos una dirección IP.';
      return;
    }
  
    
    const iocs = valueIOC.split(/[\n,]+/).map(ioc => ioc.trim()).filter(ioc => ioc);
    if (iocs.length === 0) {
      messageResult.textContent('No se detectaron direcciones ioc válidas.');
      return;
    }
  
    try {
      let results = [];
      for (const ioc of iocs) {
        // Procesar cada ioc para desanonimizar si es necesario
        const iocProcesada = procesarIOC(ioc);
        var category = detectInputType(iocProcesada);
        console.log(category)
        if(category ==='IPv4'){
        var response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${iocProcesada}`, {
          headers: {
            'x-apikey': apiKey
          }
        });
        if (!response.ok) {
          results.push(`Error al consultar ${ioc}.`);
          continue;
        }
        const data = await response.json();
        const ipAddress = iocProcesada.replaceAll(".","[.]");
        const country = data.data.attributes.country || 'Desconocido';
        const organization = data.data.attributes.as_owner || 'Desconocido';
        let dominio = 'Desconocido';
        if (data?.data?.attributes?.last_https_certificate?.subject?.CN) {
          dominio = data.data.attributes.last_https_certificate.subject.CN;
        }
        const maliciousCount = data.data.attributes.last_analysis_stats.malicious;
        const suspiciousCount = data.data.attributes.last_analysis_stats.suspicious;
  
        // Formatear la salida
        results.push(
          `IP: ${ipAddress}\n` +
          `País: ${country}\n` +
          `Organización: ${organization}\n` +
          `Dominio: ${dominio}\n`+
          `Detecciones maliciosas: ${maliciousCount}\n` +
          `Detecciones sospechosas: ${suspiciousCount}\n`
        );
        }
        else if(category ==='hash'){
          var response = await fetch(`https://www.virustotal.com/api/v3/files/${iocProcesada}`, {
            headers: {
              'x-apikey': apiKey
            }
          });
          if (!response.ok) {
            results.push(`Error al consultar ${ioc}.`);
            continue;
          }
          const data = await response.json();
          const hash = iocProcesada;
          const file = data.data.attributes.meaningful_name;
          const tag = data.data.attributes.type_tag;
          const sha256 = data.data.id;
          const maliciousCount = data.data.attributes.last_analysis_stats.malicious;
          const suspiciousCount = data.data.attributes.last_analysis_stats.suspicious;
    
          // Formatear la salida
          results.push(
            `Hash: ${hash}\n` +
            `Nombre del archivo: ${file}\n` +
            `Tag: ${tag}\n` +
            `Hash SHA-256: ${sha256}\n` +
            `Detecciones maliciosas: ${maliciousCount}\n` +
            `Detecciones sospechosas: ${suspiciousCount}\n`
          );  
        }
        else if(category ==='URL'){
          var response = await fetch(`https://www.virustotal.com/api/v3/domains/${iocProcesada}`, {
            headers: {
              'x-apikey': apiKey
            }
          });
          if (!response.ok) {
            results.push(`Error al consultar ${ioc}.`);
            continue;
          }
          const data = await response.json();
          const domain = iocProcesada.replaceAll(".","[.]");
          const maliciousCount = data.data.attributes.last_analysis_stats.malicious;
          const suspiciousCount = data.data.attributes.last_analysis_stats.suspicious;
    
          // Formatear la salida
          results.push(
            `Dominio: ${domain}\n` +
            `Detecciones maliciosas: ${maliciousCount}\n` +
            `Detecciones sospechosas: ${suspiciousCount}\n`
          );
        }
      }
      if (category ==='Desconocido'){
        messageResult.textContent = 'El dato ingresado es desconocido.'
      }else{ 
        messageResult.textContent = 'Los IOCs analizados fueron copiados a su portapapeles.';
      }
      navigator.clipboard.writeText(results.join('\n'))
        .then(() => {
          
        })
        .catch(err => {
          messageResult.textContent = 'Error al copiar al portapapeles:', err;
        });
  
    } catch (error) {
      messageResult.textContent = 'Error al verificar las IPs.',error;
    }
  });
    
    