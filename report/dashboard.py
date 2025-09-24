# report/dashboard.py

import pandas as pd
from jinja2 import Template

def generate_html_dashboard(csv_path, output_path="results/rapport_audit_graphs.html"):
    # Charger le fichier CSV
    df = pd.read_csv(csv_path, sep=",", on_bad_lines="skip")

    # Identifier les colonnes des règles dynamiquement
    rule_columns = [col for col in df.columns if col.endswith("_compliant")]
    rule_details_columns = [col.replace("_compliant", "_details") for col in rule_columns]

    # Calculer les statistiques pour chaque règle
    rule_stats = []
    for rule_col in rule_columns:
        rule_name = rule_col.replace("_compliant", "")
        compliant_count = df[rule_col].sum()
        total_count = len(df)
        compliance_percentage = round(100 * compliant_count / total_count, 1)
        rule_stats.append({
            "name": rule_name,
            "compliant": compliant_count,
            "non_compliant": total_count - compliant_count,
            "percentage": compliance_percentage
        })

    # Template HTML dynamique
    html_template = """
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Audit Réseau – Rapport Dynamique</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
        <style>
            body { font-family: 'Roboto', sans-serif; margin: 40px; background-color: #f4f6f9; color: #34495e; }
            h1 { color: #2c3e50; text-align: center; margin-bottom: 20px; }
            .summary { margin-bottom: 30px; text-align: center; }
            .summary p { font-weight: 500; font-size: 1.1em; }
            .charts { display: flex; flex-wrap: wrap; gap: 40px; justify-content: center; margin-bottom: 40px; }
            .chart-container { width: 300px; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; background-color: #ffffff; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); }
            th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
            th { background-color: #34495e; color: white; font-weight: 500; }
            tr:nth-child(even) { background-color: #f9f9f9; }
            tr:hover { background-color: #f1f1f1; }
            .ok { background-color: #c8e6c9; color: #2e7d32; font-weight: bold; }
            .fail { background-color: #ffcdd2; color: #c62828; font-weight: bold; }
            @media (max-width: 768px) {
                .chart-container { width: 100%; }
                table { font-size: 0.9em; }
            }
        </style>
    </head>
    <body>
        <h1>Rapport d'Audit Réseau</h1>
        <div class="summary">
            <p>🧮 Équipements audités : {{ total }}</p>
            {% for stat in rule_stats %}
            <p>✅ {{ stat.name }} : {{ stat.percentage }}% conformes</p>
            {% endfor %}
        </div>

        <div class="charts">
            {% for stat in rule_stats %}
            <div class="chart-container">
                <canvas id="{{ stat.name }}Chart"></canvas>
            </div>
            {% endfor %}
        </div>

        <table>
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Hostname</th>
                    <th>Modèle</th>
                    <th>Firmware</th>
                    <th>Durée (s)</th>
                    {% for rule in rule_columns %}
                    <th>{{ rule.replace('_compliant', '') }}</th>
                    {% endfor %}
                </tr>
            </thead>
            <tbody>
                {% for row in data %}
                <tr>
                    <td>{{ row.ip }}</td>
                    <td>{{ row.hostname }}</td>
                    <td>{{ row.model }}</td>
                    <td>{{ row.firmware }}</td>
                    <td>{{ row.duration }}</td>
                    {% for rule, details in zip(rule_columns, rule_details_columns) %}
                    <td class="{{ 'ok' if row[rule] else 'fail' }}">{{ row[details] }}</td>
                    {% endfor %}
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <script>
            {% for stat in rule_stats %}
            const {{ stat.name }}Data = {
                labels: ['Conformes', 'Non conformes'],
                datasets: [{
                    data: [{{ stat.compliant }}, {{ stat.non_compliant }}],
                    backgroundColor: ['#4CAF50', '#F44336']
                }]
            };

            new Chart(document.getElementById('{{ stat.name }}Chart'), {
                type: 'pie',
                data: {{ stat.name }}Data,
                options: {
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });
            {% endfor %}
        </script>
    </body>
    </html>
    """

    # Rendu du template avec les données
    template = Template(html_template)
    rendered_html = template.render(
        data=df.to_dict(orient="records"),
        total=len(df),
        rule_columns=rule_columns,
        rule_details_columns=rule_details_columns,
        rule_stats=rule_stats,
        zip=zip  # Ajout de zip ici
    )

    # Écrire le fichier HTML
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)

    print(f"📊 Rapport HTML (dynamique) généré : {output_path}")