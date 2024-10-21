# Usa una imagen base de Python
FROM python:3.12

# Establece el directorio de trabajo
WORKDIR /app

# Copia el archivo de requisitos y el resto de la aplicación
COPY requirements.txt ./

# Instala las dependencias
RUN pip3 install -r requirements.txt

# Copia el código de la aplicación al contenedor
COPY . .

# Expone el puerto en el que se ejecutará la aplicación
EXPOSE 8000

# Comando para ejecutar la aplicación
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
