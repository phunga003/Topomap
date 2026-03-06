
if [ ! -d "build/" ]; then
    echo "Build folder not found. Creating directory"
    mkdir -p build 
fi

echo "Building..."
cd build && cmake .. && make && cd ..