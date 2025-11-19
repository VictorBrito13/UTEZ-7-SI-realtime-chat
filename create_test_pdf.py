#!/usr/bin/env python3
"""
Generador de PDF de prueba simple usando reportlab
"""

def create_simple_pdf():
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from datetime import datetime
        import os
        
        # Obtener ruta del directorio actual
        current_dir = os.path.dirname(os.path.abspath(__file__))
        pdf_path = os.path.join(current_dir, "test_document.pdf")
        
        # Crear PDF
        c = canvas.Canvas(pdf_path, pagesize=letter)
        width, height = letter
        
        # Título
        c.setFont("Helvetica-Bold", 24)
        c.drawString(50, height - 50, "DOCUMENTO DE PRUEBA")
        
        # Fecha
        c.setFont("Helvetica", 10)
        c.drawString(50, height - 80, f"Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        
        # Contenido
        c.setFont("Helvetica", 12)
        y = height - 120
        
        lines = [
            "Este es un documento de prueba para firmar digitalmente.",
            "",
            "El documento contiene:",
            "• Un título",
            "• La fecha y hora actual",
            "• Este texto de prueba",
            "",
            "Después de firmar, el PDF será guardado en el servidor",
            "con la firma digital agregada.",
            "",
            "Usuario: __________________",
            "",
            "Firma: _____________________",
        ]
        
        for line in lines:
            c.drawString(50, y, line)
            y -= 20
        
        # Pie de página
        c.setFont("Helvetica-Oblique", 8)
        c.drawString(50, 30, "Documento generado automáticamente para pruebas")
        
        c.save()
        print(f"✅ PDF de prueba creado: {pdf_path}")
        return True
        
    except ImportError as e:
        print(f"❌ No se pudo importar reportlab: {e}")
        print("   Instálalo con: pip install reportlab")
        return False
    except Exception as e:
        print(f"❌ Error creando PDF: {e}")
        return False

if __name__ == "__main__":
    create_simple_pdf()
