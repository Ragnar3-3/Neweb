from flask import Flask, render_template, request
import math

app = Flask(__name__)

def roundup(value):
    return math.ceil(value * 10) / 10

def calculate_cvss(attack_vector, attack_complexity, privilege_required, user_interaction,
                  impact_conf, impact_integ, impact_avail, scope):
    # Convertir valores de cadena a números
    metrics = {
        'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
        'AC': {'L': 0.77, 'H': 0.44},
        'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},
        'UI': {'N': 0.85, 'R': 0.62},
        'Impact': {'H': 0.56, 'L': 0.22, 'N': 0}
    }
    
    # Obtener valores numéricos
    av_value = metrics['AV'][attack_vector]
    ac_value = metrics['AC'][attack_complexity]
    pr_value = metrics['PR'][privilege_required]
    ui_value = metrics['UI'][user_interaction]
    conf_value = metrics['Impact'][impact_conf]
    integ_value = metrics['Impact'][impact_integ]
    avail_value = metrics['Impact'][impact_avail]

    # Calcular ISCBase
    isc_base = 1 - ((1 - conf_value) * (1 - integ_value) * (1 - avail_value))

    # Calcular Impact subscore
    if scope == 'U':  # Unchanged
        impact = 6.42 * isc_base
    else:  # Changed
        impact = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)

    # Calcular Exploitability subscore
    exploitability = 8.22 * av_value * ac_value * pr_value * ui_value

    # Calcular Base Score
    if impact <= 0:
        base_score = 0
    else:
        if scope == 'U':
            base_score = roundup(min(impact + exploitability, 10))
        else:
            base_score = roundup(min(1.08 * (impact + exploitability), 10))

    return round(base_score, 1)

def get_severity_level(score):
    """Determina el nivel de severidad basado en la puntuación CVSS."""
    if score >= 9.0:
        return "Crítico"
    elif score >= 7.0:
        return "Alto"
    elif score >= 4.0:
        return "Medio"
    elif score > 0.0:
        return "Bajo"
    else:
        return "Ninguno"

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    severity = None
    vector_string = None
    
    if request.method == 'POST':
        # Obtener valores del formulario
        attack_vector = request.form['attack_vector']
        attack_complexity = request.form['attack_complexity']
        privilege_required = request.form['privilege_required']
        user_interaction = request.form['user_interaction']
        scope = request.form['scope']
        impact_conf = request.form['impact_conf']
        impact_integ = request.form['impact_integ']
        impact_avail = request.form['impact_avail']
        
        # Calcular puntuación CVSS
        result = calculate_cvss(
            attack_vector,
            attack_complexity,
            privilege_required,
            user_interaction,
            impact_conf,
            impact_integ,
            impact_avail,
            scope
        )
        
        # Determinar nivel de severidad
        severity = get_severity_level(result)
        
        # Generar vector string CVSS
        vector_string = f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privilege_required}/UI:{user_interaction}/S:{scope}/C:{impact_conf}/I:{impact_integ}/A:{impact_avail}"
    
    return render_template('index.html', result=result, severity=severity, vector_string=vector_string)

if __name__ == '__main__':
    app.run(debug=True)