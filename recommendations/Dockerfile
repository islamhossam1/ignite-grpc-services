FROM python

RUN mkdir /service
# download from PackageCLoud
# python gzip 
COPY protobufs/ /service/protobufs/
COPY recommendations/ /service/recommendations/
WORKDIR /service/recommendations
RUN python -m pip install --upgrade pip
RUN python -m pip install -r requirements.txt
RUN python -m grpc_tools.protoc -I ../protobufs --python_out=. \
    --grpc_python_out=. ../protobufs/recommendations.proto

# EXPOSE 50051
ENTRYPOINT [ "python", "recommendation_service.py" ]